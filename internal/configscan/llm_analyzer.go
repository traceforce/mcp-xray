package configscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"mcpxray/internal/llm"
	"mcpxray/proto"
)

const (
	LLM_TYPE_UNKNOWN   = 0
	LLM_TYPE_ANTHROPIC = 1
	LLM_TYPE_OPENAI    = 2
	LLM_TYPE_BEDROCK   = 3
)

// Batch size map: maps LLM type to max batch size bytes based on MAX_TOKENS constants
var maxBatchSizeBytesMap = map[int]int{
	llm.LLM_TYPE_ANTHROPIC: llm.MAX_TOKENS_ANTHROPIC,
	llm.LLM_TYPE_OPENAI:    llm.MAX_TOKENS_OPENAI,
	llm.LLM_TYPE_AWS:       llm.MAX_TOKENS_AWS,
}

// LLMAnalyzer analyzes MCP tools for security risks using an LLM
type LLMAnalyzer struct {
	llmClient *llm.LLMClient
}

var _ ToolsAnalyzer = (*LLMAnalyzer)(nil)

// NewLLMAnalyzerFromEnvWithModel creates a new LLM analyzer from environment variables with an optional model override
func NewLLMAnalyzerFromEnvWithModel(model string) (*LLMAnalyzer, error) {
	llmClient, err := llm.NewLLMClientFromEnvWithModel(model, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &LLMAnalyzer{
		llmClient: llmClient,
	}, nil
}

// SecurityFinding represents a security finding from LLM analysis
type SecurityFinding struct {
	ToolName string `json:"tool_name,omitempty"` // Required for batch analysis
	Severity string `json:"severity"`            // "low", "medium", "high", "critical"
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Message  string `json:"message"`
	Category string `json:"category,omitempty"` // e.g., "command_injection", "path_traversal", etc.
}

// AnalyzeTools analyzes multiple tools for security risks in a single LLM call
func (a *LLMAnalyzer) AnalyzeTools(ctx context.Context, tools []Tool, mcpServerName string, configPath string) ([]proto.Finding, error) {
	if len(tools) == 0 {
		return []proto.Finding{}, nil
	}

	var allFindings []proto.Finding

	// Get max batch size bytes based on LLM type
	llmType := a.llmClient.GetType()
	maxBatchSizeBytes, ok := maxBatchSizeBytesMap[llmType]
	if !ok {
		return nil, fmt.Errorf("unsupported LLM type: %d", llmType)
	}

	// Batch tools based on size (name + description) until reaching maxBatchSizeBytes
	i := 0
	for i < len(tools) {
		var batch []Tool
		currentBatchSize := 0
		startIdx := i
		endIdx := startIdx

		// Add tools until we reach the size limit
		for j := startIdx; j < len(tools); j++ {
			tool := tools[j]
			toolSize := len(tool.Name) + len(tool.Description)
			fmt.Printf("Tool %d: %s (%d bytes)\n", j+1, tool.Name, toolSize)

			// If adding this tool would exceed the limit and we already have tools in the batch, stop
			// Always add at least one tool, even if it exceeds the limit
			if len(batch) > 0 && currentBatchSize+toolSize > maxBatchSizeBytes {
				break
			}

			batch = append(batch, tool)
			currentBatchSize += toolSize
			endIdx = j
		}
		i = endIdx + 1

		fmt.Printf("Analyzing batch %d-%d of %d tools for server %s (batch size: %d tools, %d bytes)\n",
			startIdx+1, endIdx+1, len(tools), mcpServerName, len(batch), currentBatchSize)
		// Build the prompt for batch LLM analysis
		prompt := a.buildBatchAnalysisPrompt(batch)

		// Call the LLM
		response, err := a.callLLM(ctx, prompt)
		if err != nil {
			return nil, fmt.Errorf("failed to call LLM: %w", err)
		}

		// Parse the response
		findings, err := a.parseBatchLLMResponse(response, batch, mcpServerName, configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse LLM response: %w", err)
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// buildBatchAnalysisPrompt creates a prompt for analyzing multiple tools
func (a *LLMAnalyzer) buildBatchAnalysisPrompt(tools []Tool) string {
	var toolsList strings.Builder
	for i, tool := range tools {
		toolsList.WriteString(fmt.Sprintf("\nTool %d:\n", i+1))
		toolsList.WriteString(fmt.Sprintf("  Name: %s\n", tool.Name))
		toolsList.WriteString(fmt.Sprintf("  Description: %s\n", tool.Description))
	}

	return fmt.Sprintf(`Analyze the following MCP tools for security risks. Focus on:
1. Tool name: Does it suggest dangerous operations (e.g., file deletion, command execution, network access)?
2. Tool description: Does it describe operations that could be exploited?

Return a JSON object with a "results" field containing an array of security findings. Each finding should have:
- tool_name: The name of the tool this finding applies to. It should be an exact match to the tool name in the tools list.
- severity: "low", "medium", "high", or "critical"
- rule_id: A unique identifier for the type of risk (e.g., "command_injection", "path_traversal")
- title: A brief title describing the risk
- message: A detailed explanation of the security risk
- category: Optional category of the vulnerability

Return ONLY valid JSON, no markdown, no code fences, no additional text.

Tools to analyze:%s

JSON Response:`, toolsList.String())
}

// callLLM calls the LLM API
func (a *LLMAnalyzer) callLLM(ctx context.Context, userPrompt string) (string, error) {
	systemPrompt := `You are a security analyst specializing in analyzing API tools and schemas for security vulnerabilities. 
Analyze the provided tool information and return a JSON array of security findings.
Each finding must have: severity, rule_id, title, message, and optionally category.
Return ONLY valid JSON, no markdown formatting, no code fences.`

	content, err := a.llmClient.ChatClient.Chat(ctx, systemPrompt, []llm.ChatMessage{
		{Role: "user", Content: userPrompt},
	})
	if err != nil {
		return "", err
	}

	// Check if response is empty
	if content == "" {
		return "", fmt.Errorf("LLM returned empty response")
	}

	// Strip markdown code fences if present - handle various formats
	content = a.stripMarkdownCodeFences(content)

	// Check again after trimming
	if content == "" {
		return "", fmt.Errorf("LLM response is empty after trimming markdown")
	}

	return content, nil
}

// parseBatchLLMResponse parses the batch LLM response and converts it to proto.Finding
func (a *LLMAnalyzer) parseBatchLLMResponse(response string, tools []Tool, mcpServerName string, configPath string) ([]proto.Finding, error) {
	// Validate response is not empty
	if response == "" {
		return nil, fmt.Errorf("LLM response is empty, cannot parse JSON")
	}

	// Create a map of tool names to tools for quick lookup
	toolMap := make(map[string]Tool)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}

	var findings []SecurityFinding

	// Try to parse as wrapped object with "results" field (expected format for batch)
	var wrapped struct {
		Results []SecurityFinding `json:"results"`
	}
	if err := json.Unmarshal([]byte(response), &wrapped); err == nil && len(wrapped.Results) > 0 {
		findings = wrapped.Results
	} else {
		// Fallback: try to parse as direct array
		if err2 := json.Unmarshal([]byte(response), &findings); err2 != nil {
			// Include a snippet of the response in the error for debugging
			responseSnippet := response
			if len(responseSnippet) > 200 {
				responseSnippet = responseSnippet[:200] + "..."
			}
			return nil, fmt.Errorf("failed to parse LLM response as JSON (response length: %d, snippet: %q): %v (also tried wrapped format: %v)", len(response), responseSnippet, err2, err)
		}
	}

	// Convert to proto.Finding, mapping findings to their respective tools
	protoFindings := make([]proto.Finding, 0, len(findings))
	for _, f := range findings {
		// Determine which tool this finding belongs to
		var targetTool Tool
		if f.ToolName != "" {
			// Finding explicitly specifies tool name
			if tool, ok := toolMap[f.ToolName]; ok {
				targetTool = tool
			} else {
				// Tool name not found, skip this finding or use first tool as fallback
				continue
			}
		} else {
			// No tool name specified, this shouldn't happen in batch mode but handle gracefully
			if len(tools) > 0 {
				targetTool = tools[0]
			} else {
				continue
			}
		}

		severity := a.mapSeverity(f.Severity)
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = "llm_analyzer_finding"
		}

		// Truncate description to first 1000 characters
		truncDesc := toolMap[targetTool.Name].Description
		if len(truncDesc) > 1000 {
			truncDesc = truncDesc[:1000]
		}

		protoFindings = append(protoFindings, proto.Finding{
			Tool:          "llm_analyzer",
			Type:          proto.FindingType_FINDING_TYPE_SAST,
			Severity:      severity,
			RuleId:        ruleID,
			Title:         f.Title,
			McpServerName: mcpServerName,
			McpToolName:   targetTool.Name,
			File:          configPath,
			Message:       f.Message + " Original tool description: " + truncDesc,
		})
	}

	return protoFindings, nil
}

// stripMarkdownCodeFences removes markdown code fences from the content
// Handles various formats: ```json, ```, with or without newlines
func (a *LLMAnalyzer) stripMarkdownCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// Try to find JSON content by looking for the first { and last }
	// This handles cases where there might be text or backticks before/after
	firstBrace := strings.Index(content, "{")
	lastBrace := strings.LastIndex(content, "}")

	if firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace {
		// Extract just the JSON portion
		content = content[firstBrace : lastBrace+1]
	} else {
		// Fallback to string manipulation if JSON braces not found
		// Remove opening code fences (with or without language specifier)
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSpace(content)

		// Remove closing code fences (handle multiple cases)
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)

		// Remove any remaining standalone backticks
		content = strings.ReplaceAll(content, "```", "")
		content = strings.TrimSpace(content)
	}

	return content
}

// mapSeverity maps string severity to proto.RiskSeverity
func (a *LLMAnalyzer) mapSeverity(severity string) proto.RiskSeverity {
	severity = strings.ToLower(strings.TrimSpace(severity))
	switch severity {
	case "critical":
		return proto.RiskSeverity_RISK_SEVERITY_CRITICAL
	case "high":
		return proto.RiskSeverity_RISK_SEVERITY_HIGH
	case "medium":
		return proto.RiskSeverity_RISK_SEVERITY_MEDIUM
	case "low":
		return proto.RiskSeverity_RISK_SEVERITY_LOW
	default:
		return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}
