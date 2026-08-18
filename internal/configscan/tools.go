package configscan

import (
	"context"
	"encoding/json"
	"errors"
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

func NewToolsScanner(configPath string, analyzerType string, model string, toolsOutputFile string, maxRetries int) (*ToolsScanner, error) {
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
		llmClient, err := llm.NewLLMClientFromEnvWithModel(model, 30*time.Second, maxRetries)
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

// NewToolsScannerForDump creates a ToolsScanner that only lists tools. No
// analyzer is configured, so DumpTools must be used instead of Scan. DumpTools
// returns the tools data without writing; use WriteToolsJSON to persist it.
func NewToolsScannerForDump(configPath string) *ToolsScanner {
	return &ToolsScanner{
		MCPconfigPath: configPath,
		toolsAnalyzer: nil,
	}
}

// serverToolsResult is the outcome of connecting to a single MCP server and
// listing its tools. Exactly one of data or finding is set: data holds the
// listed tools, while finding describes a connection or listing failure.
type serverToolsResult struct {
	data    *libmcp.ServerToolsData
	finding *proto.Finding
}

// listAllServerTools connects to every MCP server in the config, lists its
// tools, and returns a per-server result. Connection and listing errors are
// captured as findings rather than aborting the whole run.
func (s *ToolsScanner) listAllServerTools(ctx context.Context) ([]serverToolsResult, error) {
	// Parse configPath
	servers, err := libmcp.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Tools scanner scanning %d MCP servers\n", len(servers))

	var results []serverToolsResult

	// Add 60 seconds context timeout
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	for _, server := range servers {
		session, err := libmcp.NewSDKSession(ctx, server)
		if err != nil {
			// Handle connection errors gracefully - continue with other servers
			fmt.Printf("Warning: Failed to connect to MCP server '%s': %v\n", server.Name, err)
			var dcrErr *libmcp.DCRUnauthorizedError
			msg := fmt.Sprintf("Could not establish connection to MCP server '%s'. The server may not be running, the endpoint may be unreachable, or the transport type may not be supported. Error: %v", server.Name, err)
			if errors.As(err, &dcrErr) {
				msg = dcrErr.Error()
			}
			results = append(results, serverToolsResult{finding: &proto.Finding{
				Tool:          "tools-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "connection_failed",
				Title:         "Failed to connect to MCP server",
				McpServerName: server.Name,
				File:          s.MCPconfigPath,
				Message:       msg,
			}})
			continue
		}
		defer session.Close()

		fmt.Printf("Listing tools for server %s\n", server.Name)

		listToolsResult, err := session.Session.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			// If the error is a 401 Unauthorized error, report a medium severity finding
			// and suggest the user to check the OAuth scopes.
			if strings.Contains(err.Error(), "401") {
				results = append(results, serverToolsResult{finding: &proto.Finding{
					Tool:          "tools-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
					RuleId:        "401_unauthorized",
					Title:         "MCP server returned 401 Unauthorized error",
					McpServerName: server.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("Authorization issue: Failed to get tools from MCP server '%s' due to 401 Unauthorized error. This may indicate missing or invalid authentication credentials, or insufficient OAuth scopes. Error: %v", server.Name, err),
				}})
				continue
			}
			// Handle other errors gracefully too
			fmt.Printf("Warning: Failed to list tools for MCP server '%s': %v\n", server.Name, err)
			results = append(results, serverToolsResult{finding: &proto.Finding{
				Tool:          "tools-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "tools_list_failed",
				Title:         "Failed to list tools from MCP server",
				McpServerName: server.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("Could not retrieve tools from MCP server '%s'. Error: %v", server.Name, err),
			}})
			continue
		}

		if len(listToolsResult.Tools) == 0 {
			continue
		}

		results = append(results, serverToolsResult{data: &libmcp.ServerToolsData{
			Server: server.Name,
			Tools:  enrichTools(listToolsResult.Tools),
		}})
	}

	return results, nil
}

func (s *ToolsScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	results, err := s.listAllServerTools(ctx)
	if err != nil {
		return nil, err
	}

	var allFindings []*proto.Finding
	var serverToolsData []libmcp.ServerToolsData

	for _, result := range results {
		if result.finding != nil {
			allFindings = append(allFindings, result.finding)
			continue
		}

		serverToolsData = append(serverToolsData, *result.data)

		findings, err := s.toolsAnalyzer.AnalyzeTools(ctx, rawTools(result.data.Tools), result.data.Server, s.MCPconfigPath)
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

// DumpTools lists the tools exposed by every MCP server in the config, without
// running any tool analysis or writing to disk. Connection and listing failures
// are returned as findings so callers can surface them, but no security scanning
// is performed. Callers can aggregate the returned data across multiple configs
// and persist it once with WriteToolsJSON.
func (s *ToolsScanner) DumpTools(ctx context.Context) ([]libmcp.ServerToolsData, []*proto.Finding, error) {
	results, err := s.listAllServerTools(ctx)
	if err != nil {
		return nil, nil, err
	}

	var serverToolsData []libmcp.ServerToolsData
	var connectionFindings []*proto.Finding

	for _, result := range results {
		if result.finding != nil {
			connectionFindings = append(connectionFindings, result.finding)
			continue
		}
		serverToolsData = append(serverToolsData, *result.data)
	}

	return serverToolsData, connectionFindings, nil
}

// WriteToolsJSON writes the collected tools data for one or more servers to the
// given JSON file, overwriting any existing content.
func WriteToolsJSON(outputFile string, serverToolsData []libmcp.ServerToolsData) error {
	// Always emit a JSON array, even when there are no servers.
	if serverToolsData == nil {
		serverToolsData = []libmcp.ServerToolsData{}
	}

	for _, sd := range serverToolsData {
		printActionRollup(sd)
	}

	jsonData, err := json.MarshalIndent(serverToolsData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tools data: %w", err)
	}

	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write tools file: %w", err)
	}

	fmt.Printf("Tools data written to %s\n", outputFile)
	return nil
}

// enrichTools classifies each tool's read/write/delete actions.
func enrichTools(tools []*mcp.Tool) []libmcp.EnrichedTool {
	enriched := make([]libmcp.EnrichedTool, len(tools))
	for i, tool := range tools {
		enriched[i] = libmcp.EnrichedTool{
			Actions: actionStrings(ClassifyToolActions(tool)),
			Tool:    tool,
		}
	}
	return enriched
}

// rawTools extracts the underlying MCP tools from enriched wrappers.
func rawTools(enriched []libmcp.EnrichedTool) []*mcp.Tool {
	tools := make([]*mcp.Tool, len(enriched))
	for i, et := range enriched {
		tools[i] = et.Tool
	}
	return tools
}

// printActionRollup prints a one-line count of tools that include each action.
func printActionRollup(sd libmcp.ServerToolsData) {
	var readN, writeN, deleteN, unknownN int
	for _, et := range sd.Tools {
		for _, a := range et.Actions {
			switch ToolAction(a) {
			case ToolActionRead:
				readN++
			case ToolActionWrite:
				writeN++
			case ToolActionDelete:
				deleteN++
			case ToolActionUnknown:
				unknownN++
			}
		}
	}
	fmt.Printf("%s: %d read, %d write, %d delete, %d unknown\n", sd.Server, readN, writeN, deleteN, unknownN)
}

// writeToolsToJSON writes the tools data for all servers to a JSON file
func (s *ToolsScanner) writeToolsToJSON(serverToolsData []libmcp.ServerToolsData) error {
	// If no output file specified, generate filename based on timestamp
	if len(s.toolsOutputFile) == 0 {
		s.toolsOutputFile = fmt.Sprintf("tools_summary_%v.json", time.Now().Format(time.RFC3339))
	}

	return WriteToolsJSON(s.toolsOutputFile, serverToolsData)
}
