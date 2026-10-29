package libmcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

// MCPServerConfig is the normalized representation returned by all parsers
type MCPServerConfig struct {
	Name              string
	Command           *string
	Args              []string
	URL               *string
	Env               map[string]string
	Headers           map[string]string
	Type              *string
	ProjectPath       *string
	RawJSON           string
	OAuthClientID     string
	OAuthClientSecret string
	RedirectURI       string // OAuth redirect URI (e.g. cursor://...; when empty, default http://127.0.0.1:8765/callback)
}

// ServerToolsData represents tools data for a single server
type ServerToolsData struct {
	Server string      `json:"server"`
	Tools  []*mcp.Tool `json:"tools"`
}
