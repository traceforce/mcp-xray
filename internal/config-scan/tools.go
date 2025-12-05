package configscan

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"SecureMCP/internal/build"
	"SecureMCP/internal/config_parser"
	"SecureMCP/proto"
)

type ToolsScanner struct {
	MCPconfigPath string
	scannerConfig *ScannerConfig
}

func NewToolsScanner(configPath string, scannerConfig *ScannerConfig) *ToolsScanner {
	return &ToolsScanner{
		MCPconfigPath: configPath,
		scannerConfig: scannerConfig,
	}
}

func (s *ToolsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// Parse configPath
	servers, err := config_parser.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	for _, server := range servers {
		fmt.Println(server.RawJSON)
		tools, err := s.GetTools(ctx, server)
		if err != nil {
			return nil, err
		}
		for _, tool := range tools {
			fmt.Printf("Name: %s\nDescription: %s\n\n", tool.Name, tool.Description)
		}
	}

	// Return tools
	return nil, nil
}

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
func (s *ToolsScanner) GetTools(ctx context.Context, cfg config_parser.MCPServerConfig) ([]Tool, error) {
	transport := ClassifyTransport(cfg)

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
func (s *ToolsScanner) getToolsSTDIO(ctx context.Context, cfg config_parser.MCPServerConfig) ([]Tool, error) {

	session, err := newMCPStdioSession(ctx, cfg, s.scannerConfig.userAccount)
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
func (s *ToolsScanner) getToolsHTTP(ctx context.Context, cfg config_parser.MCPServerConfig) ([]Tool, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("no URL specified for HTTP transport")
	}

	session := getOrCreateHTTPSession(*cfg.URL, cfg.Headers)

	// Standard MCP flow: initialize first, then tools/list
	initReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": MCPProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    build.Name,
				"version": build.Version,
			},
		},
		ID: int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	initResp, err := session.sendRequest(ctx, initReq)
	if err != nil {
		// If initialize fails, try direct tools/list (some servers allow this)
		return s.getToolsDirectHTTP(ctx, session, cfg)
	}

	if initResp.Error != nil {
		// If initialize has an error, try direct approach
		return s.getToolsDirectHTTP(ctx, session, cfg)
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
		return s.getToolsDirectHTTP(ctx, session, cfg)
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
func (s *ToolsScanner) getToolsDirectHTTP(ctx context.Context, session *MCPSession, cfg config_parser.MCPServerConfig) ([]Tool, error) {
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
