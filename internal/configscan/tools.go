package configscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	configparser "mcpxray/internal/configparser"
	metadata "mcpxray/internal/metadata"
	"mcpxray/proto"
)

type ToolsAnalyzer interface {
	AnalyzeTools(ctx context.Context, tools []Tool, mcpServerName string, configPath string) ([]proto.Finding, error)
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
		llmAnalyzer, err := NewLLMAnalyzerFromEnvWithModel(model)
		if err != nil {
			return nil, err
		}
		return &ToolsScanner{
			MCPconfigPath:   configPath,
			toolsAnalyzer:   llmAnalyzer,
			toolsOutputFile: toolsOutputFile,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported analyzer type: %s", analyzerType)
	}
}

func (s *ToolsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// Parse configPath
	servers, err := configparser.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Tools scanner scanning %d MCP servers\n", len(servers))

	var allFindings []proto.Finding
	var serverToolsData []ServerToolsData

	for _, server := range servers {
		tools, err := s.GetTools(ctx, server)
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
		serverToolsData = append(serverToolsData, ServerToolsData{
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

/**********************************Tool helper functions*****************************************/
const (
	MCPTimeout         = 5 * time.Second
	MCPProtocolVersion = "2025-06-18"
	MCPJSONRPCVersion  = "2.0"
)

var (
	requestIDCounter int64
	httpSessions     sync.Map // url + headers -> *MCPSession
)

// Tool represents an MCP tool definition
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ServerToolsData represents tools data for a single server
type ServerToolsData struct {
	Server string `json:"server"`
	Tools  []Tool `json:"tools"`
}

// MCPRequest represents a JSON-RPC request to an MCP server
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// MCPResponse represents a JSON-RPC response from an MCP server
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// MCPError represents an error in an MCP response
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolsListResult represents the result of a tools/list call
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// GetTools discovers available tools from an MCP server
func (s *ToolsScanner) GetTools(ctx context.Context, cfg configparser.MCPServerConfig) ([]Tool, error) {
	transport := ClassifyTransport(cfg)

	fmt.Printf("Transport for MCP %s: %+v\n", cfg.Name, transport)

	switch transport {
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO:
		return s.getToolsSTDIO(ctx, cfg)
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP, proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE:
		return s.getToolsHTTP(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported transport type: %v", transport)
	}
}

// getToolsSTDIO gets tools using STDIO transport
func (s *ToolsScanner) getToolsSTDIO(ctx context.Context, cfg configparser.MCPServerConfig) ([]Tool, error) {

	session, err := newMCPStdioSession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
		ID:      int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	toolsResp, err := session.sendRequest(toolsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send tools/list request: %w", err)
	}

	if toolsResp.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", toolsResp.Error.Message)
	}

	var result ToolsListResult
	if err := json.Unmarshal(toolsResp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse tools result: %w", err)
	}

	return result.Tools, nil
}

// getToolsHTTP gets tools from an MCP server using HTTP transport with universal session management
func (s *ToolsScanner) getToolsHTTP(ctx context.Context, cfg configparser.MCPServerConfig) ([]Tool, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("no URL specified for HTTP transport")
	}

	session, err := getOrCreateHTTPSession(*cfg.URL, cfg.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Standard MCP flow: initialize first, then tools/list
	initReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": MCPProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    metadata.Name,
				"version": metadata.Version,
			},
		},
		ID: int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	initResp, err := session.sendRequest(ctx, initReq)
	if err != nil {
		// If initialize fails, try direct tools/list (some servers allow this)
		return s.getToolsDirectHTTP(ctx, session)
	}

	if initResp.Error != nil {
		// If initialize has an error, try direct approach
		return s.getToolsDirectHTTP(ctx, session)
	}

	// Send tools/list request (session ID will be included automatically if needed)
	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
		ID:      int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	toolsResp, err := session.sendRequest(ctx, toolsReq)
	if err != nil {
		// If tools/list fails after successful initialize, try direct approach
		return s.getToolsDirectHTTP(ctx, session)
	}

	if toolsResp.Error != nil {
		return nil, fmt.Errorf("tools/list error: %s", toolsResp.Error.Message)
	}

	var result ToolsListResult
	if err := json.Unmarshal(toolsResp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse tools result: %w", err)
	}

	return result.Tools, nil
}

// getToolsDirectHTTP tries tools/list without initialize
func (s *ToolsScanner) getToolsDirectHTTP(ctx context.Context, session *MCPSession) ([]Tool, error) {
	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
		ID:      int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	toolsResp, err := session.sendRequest(ctx, toolsReq)
	if err != nil {
		return nil, fmt.Errorf("direct tools/list failed: %w", err)
	}

	if toolsResp.Error != nil {
		return nil, fmt.Errorf("direct tools/list error: %s", toolsResp.Error.Message)
	}

	var result ToolsListResult
	if err := json.Unmarshal(toolsResp.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to parse tools result: %w", err)
	}

	return result.Tools, nil
}

// writeToolsToJSON writes the tools data for all servers to a JSON file
func (s *ToolsScanner) writeToolsToJSON(serverToolsData []ServerToolsData) error {
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
