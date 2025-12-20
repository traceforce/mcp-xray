package libmcp

// MCPServerConfig is the normalized representation returned by all parsers
type MCPServerConfig struct {
	Name        string
	Command     *string
	Args        []string
	URL         *string
	Env         map[string]string
	Headers     map[string]string
	Type        *string // Transport type from config (e.g., "stdio", "http", "sse")
	ProjectPath *string // Project path for project-scoped servers (e.g., "/Users/user1/src")
	RawJSON     string
}
