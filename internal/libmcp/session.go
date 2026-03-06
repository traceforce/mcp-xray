package libmcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	metadata "mcpxray/internal/metadata"
	"mcpxray/proto"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DCRUnauthorizedError is returned when the server does not support DCR (403),
// we attempted connection without auth, and the server responded with Unauthorized.
// Use this error's message in findings to tell users to add oauth_client_id.
type DCRUnauthorizedError struct {
	ServerName string
}

func (e *DCRUnauthorizedError) Error() string {
	return fmt.Sprintf("MCP server '%s' does not support DCR (403). Add \"oauth_client_id\" to this server in your MCP config to connect. See examples/mcp_configs/README.md.\nAttempting connection without authentication...", e.ServerName)
}

// SDKSession wraps the official MCP SDK session to match our interface
type SDKSession struct {
	Session   *mcp.ClientSession
	Client    *mcp.Client
	Type      proto.MCPTransportType
	Transport mcp.Transport
}

// NewSDKSession creates a new session using the official MCP SDK
func NewSDKSession(ctx context.Context, cfg MCPServerConfig) (*SDKSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    metadata.Name,
		Version: metadata.Version,
	}, nil)

	var transport mcp.Transport
	var dcrSkipped bool

	// Determine transport type
	transportType := ClassifyTransport(cfg)
	switch transportType {
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO:
		if cfg.Command == nil {
			return nil, fmt.Errorf("no command specified for STDIO transport")
		}

		// Build command
		commandStr := strings.TrimSpace(*cfg.Command)
		parts := strings.Fields(commandStr)
		var executable string
		var commandArgs []string

		if len(parts) > 1 {
			executable = parts[0]
			commandArgs = append(parts[1:], cfg.Args...)
		} else {
			executable = commandStr
			commandArgs = cfg.Args
		}

		cmd := exec.Command(executable, commandArgs...)
		if cfg.Env != nil {
			cmd.Env = append(os.Environ(), envToSlice(cfg.Env)...)
		}

		transport = &mcp.CommandTransport{Command: cmd}

	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP:
		httpClient, dcrSkippedAuth, err := newHTTPClient(cfg)
		if err != nil {
			return nil, err
		}
		dcrSkipped = dcrSkippedAuth
		transport = &mcp.StreamableClientTransport{
			Endpoint:   *cfg.URL,
			HTTPClient: httpClient,
		}
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE:
		httpClient, dcrSkippedAuth, err := newHTTPClient(cfg)
		if err != nil {
			return nil, err
		}
		dcrSkipped = dcrSkippedAuth
		transport = &mcp.SSEClientTransport{
			Endpoint:   *cfg.URL,
			HTTPClient: httpClient,
		}

	default:
		return nil, fmt.Errorf("unsupported transport type: %v", transportType)
	}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		if dcrSkipped && strings.Contains(err.Error(), "Unauthorized") {
			return nil, &DCRUnauthorizedError{ServerName: cfg.Name}
		}
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return &SDKSession{
		Session:   session,
		Client:    client,
		Type:      transportType,
		Transport: transport,
	}, nil
}

func newHTTPClient(cfg MCPServerConfig) (*http.Client, bool, error) {
	// Note: The official SDK does not yet support HTTP transport directly
	// Return error to fall back to custom implementation
	if cfg.URL == nil {
		return nil, false, fmt.Errorf("no URL specified for HTTP transport")
	}
	url := *cfg.URL

	// Create HTTP client with custom transport that adds headers
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
	}

	dcrSkippedAuth := false
	if !hasAccessToken(cfg.Headers) {
		oauthConfig := NewOAuthConfig(url, cfg.OAuthClientID, cfg.OAuthClientSecret, cfg.RedirectURI)
		accessToken, err := oauthConfig.OauthDiscovery()
		if err != nil {
			if errors.Is(err, ErrDCRForbidden) && cfg.OAuthClientID == "" {
				dcrSkippedAuth = true
				fmt.Printf("MCP server '%s' does not support DCR (403). Add \"oauth_client_id\" to this server in your MCP config to connect. See examples/mcp_configs/README.md.\n", cfg.Name)
			} else {
				fmt.Printf("Warning: OAuth discovery failed: %v\n", err)
			}
			fmt.Printf("Attempting connection without authentication...\n")
		} else if accessToken != "" {
			if cfg.Headers == nil {
				cfg.Headers = make(map[string]string)
			}
			cfg.Headers["Authorization"] = "Bearer " + accessToken
		}
		// If we cannot discover the access token, just continue with the existing headers
		// the server might not require authentication
	}

	// If headers are configured, wrap the transport to add them to all requests
	if len(cfg.Headers) > 0 {
		httpClient.Transport = &headerTransport{
			base:    http.DefaultTransport,
			headers: cfg.Headers,
		}
	}

	return httpClient, dcrSkippedAuth, nil
}

// Close closes the session
func (s *SDKSession) Close() error {
	// Add timeout to prevent hanging when MCP server is stuck
	done := make(chan error, 1)
	go func() {
		done <- s.Session.Close()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		// Timeout after 30 seconds - the MCP server might be stuck
		// For stdio transport, we can't force kill the process from here,
		// but at least we won't hang forever
		return fmt.Errorf("session close timed out after 30 seconds")
	}
}

// headerTransport wraps an http.RoundTripper and adds headers to all requests
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())

	// Add all configured headers to the request
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Use the base transport to perform the request
	if t.base == nil {
		t.base = http.DefaultTransport
	}
	return t.base.RoundTrip(req)
}

// Helper functions
func envToSlice(env map[string]string) []string {
	var result []string
	for k, v := range env {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// hasAccessToken checks if the headers contain an access token
func hasAccessToken(headers map[string]string) bool {
	if headers == nil {
		return false
	}
	// Check for "Authorization" key (case-sensitive since map keys are case-sensitive)
	// HTTP headers are case-insensitive, but we check the common capitalized form
	if authHeader, ok := headers["Authorization"]; ok && strings.HasPrefix(authHeader, "Bearer ") {
		return true
	}

	// Also check lowercase "authorization" in case it was stored that way
	if authHeader, ok := headers["authorization"]; ok && strings.HasPrefix(authHeader, "Bearer ") {
		return true
	}

	return false
}
