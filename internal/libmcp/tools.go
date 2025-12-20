package libmcp

import (
	"context"
	"encoding/json"
	"fmt"
)

/**********************************Tool helper functions*****************************************/

// GetTools discovers available tools from an MCP server
func GetTools(ctx context.Context, session MCPSession) ([]Tool, error) {
	switch session := session.(type) {
	case *MCPStdioSession:
		return getToolsSTDIO(ctx, session)
	case *MCPHttpSession:
		return getToolsHTTP(ctx, session)
	default:
		return nil, fmt.Errorf("unsupported session type: %T", session)
	}
}

// getToolsSTDIO gets tools using STDIO transport
func getToolsSTDIO(ctx context.Context, session *MCPStdioSession) ([]Tool, error) {

	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	toolsResp, err := session.SendRequest(ctx, toolsReq)
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
func getToolsHTTP(ctx context.Context, session *MCPHttpSession) ([]Tool, error) {

	// Send tools/list request (session ID will be included automatically if needed)
	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	toolsResp, err := session.SendRequest(ctx, toolsReq)
	if err != nil {
		// If tools/list fails after successful initialize, try direct approach
		return getToolsDirectHTTP(ctx, session)
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
func getToolsDirectHTTP(ctx context.Context, session *MCPHttpSession) ([]Tool, error) {
	toolsReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	toolsResp, err := session.SendRequest(ctx, toolsReq)
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
