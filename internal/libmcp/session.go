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
	secrets   []string           // the config's and environment's values that Redact masks
}

// Redact masks the config's secrets in an error from a call made after connect,
// such as tools/list, before it becomes an outcome reason or a finding.
func (s *SDKSession) Redact(err error) error {
	return &redactedError{msg: redact(err.Error(), s.secrets, false), err: err}
}

// connectTimeout bounds initialize unless the config sets its own, so a child
// that prints only non-JSON and waits, or a remote server that never answers,
// fails instead of hanging.
const connectTimeout = 60 * time.Second

// NewSDKSession creates a new session using the official MCP SDK
func NewSDKSession(ctx context.Context, cfg MCPServerConfig) (*SDKSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    metadata.Name,
		Version: metadata.Version,
	}, nil)

	var transport mcp.Transport
	var dcrSkipped bool
	var secrets []string  // config and environment values that must never appear in an error
	var stderr outputTail // what a stdio child wrote to stderr, for the connect error
	var stdout outputTail // what it wrote to stdout before its first message, likewise

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
				secrets = append(secrets, v)
			}
		}
		for _, v := range cfg.Env { // configured values in parts too: AUTH_HEADER="Bearer <token>"
			secrets = append(secrets, valueParts(v)...)
		}
		secrets = secretParts(append(secrets, argSecrets(commandArgs)...))
		stderr.secrets, stdout.secrets = secrets, secrets
		cmd.Stderr = &stderr
		cmd.WaitDelay = stdioPipeWait // a grandchild holding stderr open must not block Wait

		stdio, err := startStdio(cmd, &stdout)
		if err != nil {
			// exec reports only the executable token: mask a NAME=<value> before the
			// command, not the paths inherited values name (USERPROFILE, APPDATA).
			msg := "failed to connect: " + err.Error()
			if _, v, ok := strings.Cut(executable, "="); ok {
				msg = redact(msg, secretParts([]string{v}), false)
			}
			return nil, &redactedError{msg: msg, err: err}
		}
		transport = stdio

	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP:
		httpClient, dcrSkippedAuth, err := newHTTPClient(cfg)
		if err != nil {
			return nil, err
		}
		dcrSkipped = dcrSkippedAuth
		secrets = transportSecrets(cfg, httpClient)
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
		secrets = transportSecrets(cfg, httpClient)
		transport = &mcp.SSEClientTransport{
			Endpoint:   *cfg.URL,
			HTTPClient: httpClient,
		}

	default:
		return nil, fmt.Errorf("unsupported transport type: %v", transportType)
	}

	timeout := cfg.ConnectTimeout
	if timeout <= 0 {
		timeout = connectTimeout
	}
	// SSE reads its stream with the context it connects with, so that context
	// lives as long as the session; the timer cancels it only while initialize runs.
	connectCtx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(timeout, cancel)
	session, err := client.Connect(connectCtx, transport, nil)
	// A timeout only when the timer is what ended Connect: a server error that came
	// first stays as it is, even if the timer fires while the SDK cleans up.
	if !timer.Stop() && (err == nil || (errors.Is(err, context.Canceled) && ctx.Err() == nil)) {
		if err == nil {
			_ = session.Close()
		}
		err = fmt.Errorf("%w after %v", context.DeadlineExceeded, timeout)
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
		brief := redact("failed to connect: "+err.Error(), secrets, false)
		msg := brief
		if len(output) > 0 {
			// The SDK error stays last: OutcomeForError classifies by its suffix.
			msg = redact(fmt.Sprintf("failed to connect (%s): %v", strings.Join(output, "; "), err), secrets, false)
		}
		return nil, &redactedError{msg: msg, brief: brief, err: err}
	}

	return &SDKSession{
		Session:   session,
		Client:    client,
		Type:      transportType,
		Transport: transport,
		cancel:    cancel,
		secrets:   secrets,
	}, nil
}

// transportSecrets returns what a remote error can echo: the URL's and the
// headers' values, including a bearer OAuth discovery added for this client.
func transportSecrets(cfg MCPServerConfig, c *http.Client) []string {
	return remoteSecrets(*cfg.URL, c.Transport.(*headerTransport).headers)
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
				fmt.Printf("Warning: OAuth discovery failed: %s\n", redact(err.Error(), remoteSecrets(url, cfg.Headers), false))
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
