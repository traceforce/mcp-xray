package libmcp

import (
	"strings"

	"mcpxray/proto"
)

// ClassifyTransport determines the transport mechanism based on MCP server configuration
// Uses explicit Type field when available, otherwise falls back to legacy detection logic.
func ClassifyTransport(cfg MCPServerConfig) proto.MCPTransportType {
	// Use explicit type field if present (Claude Code format)
	if cfg.Type != nil && norm(*cfg.Type) != "" {
		switch norm(*cfg.Type) {
		case "stdio":
			return proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO
		case "http":
			return proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP
		case "sse":
			return proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE
		default:
			return proto.MCPTransportType_MCP_TRANSPORT_TYPE_UNKNOWN
		}
	}

	if cfg.Command != nil && norm(*cfg.Command) != "" {
		return proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO
	}
	if cfg.URL != nil && norm(*cfg.URL) != "" {
		url := norm(*cfg.URL)
		if strings.Contains(url, "/sse") {
			return proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE
		}
		return proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP
	}
	return proto.MCPTransportType_MCP_TRANSPORT_TYPE_UNKNOWN
}

func norm(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	return strings.ToLower(s)
}
