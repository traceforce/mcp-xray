package configscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"mcpxray/internal/libmcp"
	"mcpxray/internal/llm"
	"mcpxray/proto"
)

type ToolsAnalyzer interface {
	AnalyzeTools(ctx context.Context, tools []libmcp.Tool, mcpServerName string, configPath string) ([]proto.Finding, error)
}

type ToolsScanner struct {
	MCPconfigPath   string
	toolsAnalyzer   ToolsAnalyzer
	toolsOutputFile string
}

func NewToolsScanner(configPath string, analyzerType string, model string, toolsOutputFile string) (*ToolsScanner, error) {
	switch analyzerType {
	case "token":
		tokenAnalyzer, err := NewTokenAnalyzer()
		if err != nil {
			return nil, err
		}
		return &ToolsScanner{
			MCPconfigPath:   configPath,
			toolsAnalyzer:   tokenAnalyzer,
			toolsOutputFile: toolsOutputFile,
		}, nil
	case "llm":
		llmClient, err := llm.NewLLMClientFromEnvWithModel(model, 30*time.Second)
		if err != nil {
			return nil, err
		}
		return &ToolsScanner{
			MCPconfigPath:   configPath,
			toolsAnalyzer:   NewLLMAnalyzerFromEnvWithModel(llmClient),
			toolsOutputFile: toolsOutputFile,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported analyzer type: %s", analyzerType)
	}
}

func (s *ToolsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// Parse configPath
	servers, err := libmcp.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Tools scanner scanning %d MCP servers\n", len(servers))

	var allFindings []proto.Finding
	var serverToolsData []libmcp.ServerToolsData

	for _, server := range servers {
		session, err := libmcp.NewMCPSession(ctx, server)
		if err != nil {
			return nil, err
		}
		defer session.Close()

		tools, err := libmcp.GetTools(ctx, session)
		if err != nil {
			// If the error is a 401 Unauthorized error, report a medium severity finding
			// and suggest the user to check the OAuth scopes.
			if strings.Contains(err.Error(), "401") {
				allFindings = append(allFindings, proto.Finding{
					Tool:          "tools-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
					RuleId:        "401_unauthorized",
					Title:         "MCP server returned 401 Unauthorized error",
					McpServerName: server.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("Authorization issue: Failed to get tools from MCP server '%s' due to 401 Unauthorized error. This may indicate missing or invalid authentication credentials, or insufficient OAuth scopes. Error: %v", server.Name, err),
				})
				continue
			}
			return nil, err
		}

		// Collect tools data for JSON output (even if empty)
		serverToolsData = append(serverToolsData, libmcp.ServerToolsData{
			Server: server.Name,
			Tools:  tools,
		})

		if len(tools) == 0 {
			continue
		}

		findings, err := s.toolsAnalyzer.AnalyzeTools(ctx, tools, server.Name, s.MCPconfigPath)
		if err != nil {
			return nil, err
		}
		allFindings = append(allFindings, findings...)

	}

	// Write tools to JSON file
	if err := s.writeToolsToJSON(serverToolsData); err != nil {
		return nil, fmt.Errorf("failed to write tools to JSON: %w", err)
	}

	fmt.Printf("Tools scanner found %d findings\n", len(allFindings))

	return allFindings, nil
}

// writeToolsToJSON writes the tools data for all servers to a JSON file
func (s *ToolsScanner) writeToolsToJSON(serverToolsData []libmcp.ServerToolsData) error {
	// If no output file specified, generate filename based on config path
	if len(s.toolsOutputFile) == 0 {
		//skip writing tools to file
		s.toolsOutputFile = fmt.Sprintf("tools_summary_%v.json", time.Now().Format(time.RFC3339))
	}

	// Create JSON data
	jsonData, err := json.MarshalIndent(serverToolsData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tools data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(s.toolsOutputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write tools file: %w", err)
	}

	fmt.Printf("Tools data written to %s\n", s.toolsOutputFile)
	return nil
}
