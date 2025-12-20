package libmcp

import "encoding/json"

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

// ToolsListResult represents the result of a tools/list call
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}
