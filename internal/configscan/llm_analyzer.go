package configscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"SecureMCP/proto"

	"github.com/joho/godotenv"
)

// LLMAnalyzer analyzes MCP tools for security risks using an LLM
type LLMAnalyzer struct {
	apiURL  string
	apiKey  string
	model   string
	llmType string // "openai" or "anthropic"
	timeout time.Duration
	client  *http.Client
}

// LLMConfig holds configuration for the LLM analyzer
type LLMConfig struct {
	APIURL  string // e.g., "https://api.openai.com/v1/chat/completions" or "https://api.anthropic.com/v1/messages"
	APIKey  string
	Model   string // e.g., "gpt-4" or "claude-3-5-sonnet-20241022"
	LLMType string // "openai" or "anthropic"
	Timeout time.Duration
}

// NewLLMAnalyzer creates a new LLM analyzer with the given configuration
func NewLLMAnalyzer(config LLMConfig) *LLMAnalyzer {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &LLMAnalyzer{
		apiURL:  config.APIURL,
		apiKey:  config.APIKey,
		model:   config.Model,
		llmType: config.LLMType,
		timeout: config.Timeout,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// NewLLMAnalyzerFromEnv creates a new LLM analyzer from environment variables
func NewLLMAnalyzerFromEnv() *LLMAnalyzer {
	// Load environment variables from .env file (ignores error if .env doesn't exist)
	_ = godotenv.Load()

	apiURL := os.Getenv("LLM_API_URL")
	apiKey := os.Getenv("LLM_API_KEY")
	model := os.Getenv("LLM_MODEL")
	llmType := os.Getenv("LLM_TYPE")

	// Set defaults if not provided
	if apiURL == "" {
		if llmType == "anthropic" {
			apiURL = "https://api.anthropic.com/v1/messages"
		} else {
			apiURL = "https://api.openai.com/v1/chat/completions"
		}
	}
	if llmType == "" {
		llmType = "anthropic"
	}
	if model == "" {
		if llmType == "anthropic" {
			model = "claude-3-5-sonnet-20241022"
		} else {
			model = "gpt-4"
		}
	}

	return NewLLMAnalyzer(LLMConfig{
		APIURL:  apiURL,
		APIKey:  apiKey,
		Model:   model,
		LLMType: llmType,
		Timeout: 30 * time.Second,
	})
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
	if a.apiKey == "" {
		return nil, fmt.Errorf("no API key configured")
	}

	if len(tools) == 0 {
		return []proto.Finding{}, nil
	}

	// Build the prompt for batch LLM analysis
	prompt := a.buildBatchAnalysisPrompt(tools)

	// Call the LLM
	response, err := a.callLLM(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to call LLM: %w", err)
	}

	// Parse the response
	findings, err := a.parseBatchLLMResponse(response, tools, mcpServerName, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return findings, nil
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
- tool_name: The name of the tool this finding applies to (required for batch analysis)
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

	var reqBody []byte
	var err error

	if a.llmType == "anthropic" {
		reqBody, err = a.buildAnthropicRequest(systemPrompt, userPrompt)
	} else {
		reqBody, err = a.buildOpenAIRequest(systemPrompt, userPrompt)
	}
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if a.llmType == "anthropic" {
		req.Header.Set("x-api-key", a.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("content-type", "application/json")
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.apiKey))
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response based on LLM type
	var content string
	if a.llmType == "anthropic" {
		var anthropicResp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(bodyBytes, &anthropicResp); err != nil {
			return "", fmt.Errorf("failed to parse Anthropic response: %w", err)
		}
		if len(anthropicResp.Content) == 0 {
			return "", fmt.Errorf("empty response from Anthropic")
		}
		content = anthropicResp.Content[0].Text
	} else {
		var openaiResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(bodyBytes, &openaiResp); err != nil {
			return "", fmt.Errorf("failed to parse OpenAI response: %w", err)
		}
		if len(openaiResp.Choices) == 0 {
			return "", fmt.Errorf("empty response from OpenAI")
		}
		content = openaiResp.Choices[0].Message.Content
	}

	// Strip markdown code fences if present
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	return content, nil
}

// buildOpenAIRequest builds a request for OpenAI API
func (a *LLMAnalyzer) buildOpenAIRequest(systemPrompt, userPrompt string) ([]byte, error) {
	// Wrap prompt to ensure consistent JSON format with results array
	wrappedPrompt := fmt.Sprintf(`Return a JSON object with a "results" field containing an array of findings. %s`, userPrompt)

	reqBody := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": wrappedPrompt},
		},
		"temperature": 0.0,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	return json.Marshal(reqBody)
}

// buildAnthropicRequest builds a request for Anthropic API
func (a *LLMAnalyzer) buildAnthropicRequest(systemPrompt, userPrompt string) ([]byte, error) {
	// Anthropic uses a different format - combine system and user prompts
	fullPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)

	reqBody := map[string]interface{}{
		"model":      a.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{"role": "user", "content": fullPrompt},
		},
		"temperature": 0.0,
	}

	return json.Marshal(reqBody)
}

// parseLLMResponse parses the LLM response and converts it to proto.Finding
func (a *LLMAnalyzer) parseLLMResponse(response string, tool Tool, mcpServerName string, configPath string) ([]proto.Finding, error) {
	var findings []SecurityFinding

	// Try to parse as direct array
	if err := json.Unmarshal([]byte(response), &findings); err != nil {
		// Try to parse as wrapped object with "results" field
		var wrapped struct {
			Results []SecurityFinding `json:"results"`
		}
		if err2 := json.Unmarshal([]byte(response), &wrapped); err2 != nil {
			return nil, fmt.Errorf("failed to parse LLM response as JSON array or results object: %v, %v", err, err2)
		}
		findings = wrapped.Results
	}

	// Convert to proto.Finding
	protoFindings := make([]proto.Finding, 0, len(findings))
	for _, f := range findings {
		severity := a.mapSeverity(f.Severity)
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = "llm_analyzer_finding"
		}

		protoFindings = append(protoFindings, proto.Finding{
			Tool:          "llm_analyzer",
			Type:          proto.FindingType_FINDING_TYPE_SAST,
			Severity:      severity,
			RuleId:        ruleID,
			Title:         f.Title,
			McpServerName: mcpServerName,
			McpToolName:   tool.Name,
			File:          configPath,
			Message:       f.Message,
		})
	}

	return protoFindings, nil
}

// parseBatchLLMResponse parses the batch LLM response and converts it to proto.Finding
func (a *LLMAnalyzer) parseBatchLLMResponse(response string, tools []Tool, mcpServerName string, configPath string) ([]proto.Finding, error) {
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
	if err := json.Unmarshal([]byte(response), &wrapped); err == nil {
		findings = wrapped.Results
	} else {
		// Fallback: try to parse as direct array
		if err2 := json.Unmarshal([]byte(response), &findings); err2 != nil {
			return nil, fmt.Errorf("failed to parse LLM response as JSON: %v (also tried wrapped format: %v)", err2, err)
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

		protoFindings = append(protoFindings, proto.Finding{
			Tool:          "llm_analyzer",
			Type:          proto.FindingType_FINDING_TYPE_SAST,
			Severity:      severity,
			RuleId:        ruleID,
			Title:         f.Title,
			McpServerName: mcpServerName,
			McpToolName:   targetTool.Name,
			File:          configPath,
			Message:       f.Message,
		})
	}

	return protoFindings, nil
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
