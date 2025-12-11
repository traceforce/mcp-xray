package configscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	configparser "SecureMCP/internal/configparser"
	metadata "SecureMCP/internal/metadata"
	"SecureMCP/proto"
)

type ToolsScanner struct {
	MCPconfigPath string
	llmAnalyzer   *LLMAnalyzer
}

func NewToolsScanner(configPath string) *ToolsScanner {
	return &ToolsScanner{
		MCPconfigPath: configPath,
		llmAnalyzer:   NewLLMAnalyzerFromEnv(),
	}
}

func (s *ToolsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// Parse configPath
	servers, err := configparser.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	var allFindings []proto.Finding

	for _, server := range servers {
		fmt.Println(server.RawJSON)
		tools, err := s.GetTools(ctx, server)
		if err != nil {
			// Log error but continue with other servers
			fmt.Printf("Warning: failed to get tools for server %s: %v\n", server.Name, err)
			continue
		}
		if len(tools) == 0 {
			continue
		}

		fmt.Printf("Analyzing %d tools for server %s\n", len(tools), server.Name)
		// Batch analyze tools in groups of 10
		const batchSize = 10
		for i := 0; i < len(tools); i += batchSize {
			end := i + batchSize
			if end > len(tools) {
				end = len(tools)
			}
			batch := tools[i:end]
			fmt.Printf("Analyzing batch %d-%d of %d tools for server %s\n", i+1, end, len(tools), server.Name)

			findings, err := s.analyzeTools(ctx, batch, server.Name)
			if err != nil {
				// Log error but continue with other batches
				fmt.Printf("Warning: failed to analyze batch %d-%d for server %s: %v\n", i+1, end, server.Name, err)
				continue
			}
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func (s *ToolsScanner) analyzeTools(ctx context.Context, tools []Tool, mcpServerName string) ([]proto.Finding, error) {
	if s.llmAnalyzer == nil {
		return []proto.Finding{}, nil
	}
	return s.llmAnalyzer.AnalyzeTools(ctx, tools, mcpServerName, s.MCPconfigPath)
}

// formatJSON returns pretty-printed JSON when possible, or falls back to raw bytes.
func formatJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
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
