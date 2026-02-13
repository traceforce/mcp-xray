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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ToolsAnalyzer interface {
	AnalyzeTools(ctx context.Context, tools []*mcp.Tool, mcpServerName string, configPath string) ([]*proto.Finding, error)
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

func (s *ToolsScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	// Parse configPath
	servers, err := libmcp.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Tools scanner scanning %d MCP servers\n", len(servers))

	var allFindings []*proto.Finding
	var serverToolsData []libmcp.ServerToolsData

	// Add 60 seconds context timeout
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	for _, server := range servers {
		session, err := libmcp.NewSDKSession(ctx, server)
		if err != nil {
			// Handle connection errors gracefully - continue with other servers
			fmt.Printf("Warning: Failed to connect to MCP server '%s': %v\n", server.Name, err)
			// Optionally add a finding about the connection failure
			allFindings = append(allFindings, &proto.Finding{
				Tool:          "tools-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "connection_failed",
				Title:         "Failed to connect to MCP server",
				McpServerName: server.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("Could not establish connection to MCP server '%s'. The server may not be running, the endpoint may be unreachable, or the transport type may not be supported. Error: %v", server.Name, err),
			})
			continue
		}
		defer session.Close()

		fmt.Printf("Listing tools for server %s\n", server.Name)

		listToolsResult, err := session.Session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			// If the error is a 401 Unauthorized error, report a medium severity finding
			// and suggest the user to check the OAuth scopes.
			if strings.Contains(err.Error(), "401") {
				allFindings = append(allFindings, &proto.Finding{
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
			// Handle other errors gracefully too
			fmt.Printf("Warning: Failed to list tools for MCP server '%s': %v\n", server.Name, err)
			allFindings = append(allFindings, &proto.Finding{
				Tool:          "tools-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "tools_list_failed",
				Title:         "Failed to list tools from MCP server",
				McpServerName: server.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("Could not retrieve tools from MCP server '%s'. Error: %v", server.Name, err),
			})
			continue
		}

		if len(listToolsResult.Tools) == 0 {
			continue
		}

		// Collect tools data for JSON output (even if empty)
		serverToolsData = append(serverToolsData, libmcp.ServerToolsData{
			Server: server.Name,
			Tools:  listToolsResult.Tools,
		})

		findings, err := s.toolsAnalyzer.AnalyzeTools(ctx, listToolsResult.Tools, server.Name, s.MCPconfigPath)
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
