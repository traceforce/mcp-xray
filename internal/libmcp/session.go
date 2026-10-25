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
	cancel    context.CancelFunc // ends the context the transport connected with
}

// connectTimeout bounds initialize, so a child that prints only non-JSON and
// waits, or a remote server that never answers, fails instead of hanging.
var connectTimeout = 60 * time.Second

// NewSDKSession creates a new session using the official MCP SDK
func NewSDKSession(ctx context.Context, cfg MCPServerConfig) (*SDKSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    metadata.Name,
		Version: metadata.Version,
	}, nil)

	var transport mcp.Transport
	var dcrSkipped bool
	var stderr outputTail // what a stdio child wrote to stderr, for the connect error
	var stdout outputTail // the non-JSON lines it wrote to stdout, likewise

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
		// Inherited values count too: the child may echo any of them.
		for _, kv := range cmd.Environ() {
			if _, v, _ := strings.Cut(kv, "="); len(v) >= 8 { // shorter values such as "1" or "true" would mangle unrelated text
				stderr.secrets = append(stderr.secrets, v)
			}
		}
		stderr.secrets = append(stderr.secrets, argSecrets(commandArgs)...)
		stdout.secrets = stderr.secrets
		cmd.Stderr = &stderr
		cmd.WaitDelay = stdioPipeWait // a grandchild holding stderr open must not block Wait

		stdio, err := startStdio(cmd, &stdout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
		transport = stdio

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

	// SSE reads its stream with the context it connects with, so that context
	// lives as long as the session; the timer cancels it only while initialize runs.
	connectCtx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(connectTimeout, cancel)
	session, err := client.Connect(connectCtx, transport, nil)
	if !timer.Stop() {
		if err == nil {
			_ = session.Close()
			err = fmt.Errorf("%w after %v", context.DeadlineExceeded, connectTimeout)
		} else {
			err = fmt.Errorf("%w after %v (%v)", context.DeadlineExceeded, connectTimeout, err)
		}
	}
	if err != nil {
		cancel()
		if dcrSkipped && strings.Contains(err.Error(), "Unauthorized") {
			return nil, &DCRUnauthorizedError{ServerName: cfg.Name}
		}
		var output []string
		if tail := stderr.String(); tail != "" {
			output = append(output, "stderr: "+tail)
		}
		if tail := stdout.String(); tail != "" {
			output = append(output, "stdout: "+tail)
		}
		msg := "failed to connect: " + err.Error()
		if len(output) > 0 {
			// The SDK error stays last: OutcomeForError classifies by its suffix.
			msg = fmt.Sprintf("failed to connect (%s): %v", strings.Join(output, "; "), err)
		}
		return nil, &redactedError{msg: redact(msg, stderr.secrets, false), err: err}
	}

	return &SDKSession{
		Session:   session,
		Client:    client,
		Type:      transportType,
		Transport: transport,
		cancel:    cancel,
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
	if !cfg.NonInteractive && !hasAccessToken(cfg.Headers) {
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

	// Add the configured headers, and a User-Agent when they do not set one, to all requests
	httpClient.Transport = &headerTransport{
		base:    http.DefaultTransport,
		headers: cfg.Headers,
	}

	return httpClient, dcrSkippedAuth, nil
}

// Close closes the session
func (s *SDKSession) Close() error {
	if s.cancel != nil {
		defer s.cancel()
	}
	// Add timeout to prevent hanging when MCP server is stuck
	done := make(chan error, 1)
	go func() {
		done <- s.Session.Close()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		// Timeout after 30 seconds - the MCP server might be stuck.
		// For stdio, Session.Close escalates to SIGTERM and SIGKILL (stdinCloser); this only bounds how long we wait for that.
		return fmt.Errorf("session close timed out after 30 seconds")
	}
}

// headerTransport wraps an http.RoundTripper and adds the configured headers to
// all requests, plus a User-Agent when they do not set one.
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
	// Go would otherwise send User-Agent: Go-http-client/1.1, which some servers refuse.
	// An explicitly empty configured value means send none, so test presence, not emptiness.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", metadata.Name+"/"+metadata.Version)
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
