package libmcp

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPServerConfig is the normalized representation returned by all parsers
type MCPServerConfig struct {
	Name               string
	Command            *string
	Args               []string
	URL                *string
	Env                map[string]string
	Headers            map[string]string
	Type               *string
	ProjectPath        *string
	RawJSON            string
	OAuthClientID      string
	OAuthClientSecret  string
	RedirectURI        string        // OAuth redirect URI (e.g. cursor://...; when empty, default http://127.0.0.1:8765/callback)
	OAuthTokenEndpoint string        // A token endpoint off the server's own site that its stored login may use
	NonInteractive     bool          // Never start browser OAuth; a server that needs it fails to connect instead
	Credentials        Credentials   // Stored logins by server URL; a browser login is added to it
	CredentialsFile    string        // Where Credentials is saved after every change; empty keeps them in memory
	ConnectTimeout     time.Duration // How long initialize may take; 0 means 60 seconds
	skipStoredLogin    bool          // set for the browser login retried after a refreshed stored login is refused
}

// EnrichedTool wraps an MCP tool with classified action labels
// (read, write, delete, and/or unknown).
type EnrichedTool struct {
	Actions []string  `json:"permission_type"`
	Tool    *mcp.Tool `json:"tool"`
}

// ServerToolsData represents tools data for a single server
type ServerToolsData struct {
	Server string         `json:"server"`
	Tools  []EnrichedTool `json:"tools"`
}
