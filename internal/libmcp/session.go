package libmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
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
	recorder  *probeRecorder // set only for anonymous probe sessions
}

// ErrUnsupportedCredentialPath marks a config whose credentials mcp-xray cannot
// remove, so an anonymous probe would not actually be credential-free.
var ErrUnsupportedCredentialPath = errors.New("unsupported credential path")

// ProbeResponse is the transport-level evidence recorded for one JSON-RPC phase.
type ProbeResponse struct {
	Status  int    // HTTP status; 0 when no response was obtained
	Phase   string // "sse_connect", "initialize" or "tools/call"
	WWWAuth bool
	Extra   int // repeat requests in this phase beyond the first
}

// ProbeError carries the last recorded evidence when an anonymous connect fails.
type ProbeError struct {
	Response ProbeResponse
	Err      error
}

func (e *ProbeError) Error() string { return e.Err.Error() }
func (e *ProbeError) Unwrap() error { return e.Err }

// NewSDKSession creates a new session using the official MCP SDK
func NewSDKSession(ctx context.Context, cfg MCPServerConfig) (*SDKSession, error) {
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

	sess, err := connect(ctx, transport, transportType, nil)
	if err != nil {
		if dcrSkipped && strings.Contains(err.Error(), "Unauthorized") {
			return nil, &DCRUnauthorizedError{ServerName: cfg.Name}
		}
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	return sess, nil
}

// connect dials transport with a fresh client and wraps the live session.
func connect(ctx context.Context, transport mcp.Transport, transportType proto.MCPTransportType, rec *probeRecorder) (*SDKSession, error) {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    metadata.Name,
		Version: metadata.Version,
	}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	return &SDKSession{
		Session:   session,
		Client:    client,
		Type:      transportType,
		Transport: transport,
		recorder:  rec,
	}, nil
}

// NewUnauthenticatedSDKSession connects with every credential removed and records the
// transport response. It refuses any config whose credentials it cannot prove were removed.
func NewUnauthenticatedSDKSession(ctx context.Context, cfg MCPServerConfig) (*SDKSession, error) {
	if reason := UnsupportedCredentialReason(cfg); reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCredentialPath, reason)
	}

	rec := &probeRecorder{
		base:    http.DefaultTransport,
		sse:     ClassifyTransport(cfg) == proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE,
		byPhase: make(map[string]ProbeResponse),
	}
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: rec}

	var transport mcp.Transport = &mcp.StreamableClientTransport{Endpoint: *cfg.URL, HTTPClient: httpClient}
	if rec.sse {
		transport = &mcp.SSEClientTransport{Endpoint: *cfg.URL, HTTPClient: httpClient}
	}

	sess, err := connect(ctx, transport, ClassifyTransport(cfg), rec)
	if err != nil {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		// Prefer initialize: an SSE stream can open and then reject initialize.
		for _, phase := range []string{"initialize", "sse_connect"} {
			if resp, ok := rec.byPhase[phase]; ok {
				return nil, &ProbeError{Response: resp, Err: err}
			}
		}
		return nil, err
	}
	return sess, nil
}

// UnsupportedCredentialReason explains why cfg cannot be probed anonymously, or "" when it can.
func UnsupportedCredentialReason(cfg MCPServerConfig) string {
	if ClassifyTransport(cfg) == proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO {
		return "credential removal cannot be established for stdio transports"
	}
	for k := range cfg.Headers {
		if !strings.EqualFold(k, "Authorization") {
			return "non-Authorization headers configured"
		}
	}
	if cfg.URL == nil {
		return "no URL configured"
	}
	if u, err := neturl.Parse(*cfg.URL); err != nil {
		return "the configured URL could not be parsed"
	} else if u.User != nil || u.RawQuery != "" {
		return "the configured URL may carry credentials"
	}
	if ClassifyTransport(cfg) == proto.MCPTransportType_MCP_TRANSPORT_TYPE_UNKNOWN {
		return "unsupported transport"
	}
	return ""
}

// Probe returns the recorded evidence for a JSON-RPC phase on an anonymous session.
func (s *SDKSession) Probe(phase string) (ProbeResponse, bool) {
	if s.recorder == nil {
		return ProbeResponse{}, false
	}
	s.recorder.mu.Lock()
	defer s.recorder.mu.Unlock()
	pr, ok := s.recorder.byPhase[phase]
	return pr, ok
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

// probeRecorder is the transport of a credential-free probe. It keeps one record per
// JSON-RPC phase it observes (sse_connect, initialize, tools/call) and ignores the rest.
type probeRecorder struct {
	base    http.RoundTripper
	sse     bool
	mu      sync.Mutex
	byPhase map[string]ProbeResponse
}

func (r *probeRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	// A server-supplied URL (redirect or SSE endpoint) with userinfo makes net/http add Basic auth.
	if req.Header.Get("Authorization") != "" || req.URL.User != nil {
		return nil, fmt.Errorf("%w: the request carries a credential", ErrUnsupportedCredentialPath)
	}
	phase := ""
	switch req.Method {
	case http.MethodGet:
		if r.sse {
			phase = "sse_connect"
		}
	case http.MethodPost:
		var msg struct {
			Method string `json:"method"`
		}
		// Decode the GetBody copy so the base transport sees req.Body untouched.
		if req.GetBody != nil {
			if rc, err := req.GetBody(); err == nil {
				_ = json.NewDecoder(rc).Decode(&msg)
				rc.Close()
			}
		}
		if msg.Method == "initialize" || msg.Method == "tools/call" {
			phase = msg.Method
		}
	}

	resp, err := r.base.RoundTrip(req)
	// A 3xx hop is not the evidence; the followed hop is recorded instead.
	if phase != "" && !(err == nil && resp.StatusCode/100 == 3) {
		r.record(phase, resp, err)
	}
	return resp, err
}

// record stores the first evidence for phase; a repeat request in that phase only bumps Extra.
func (r *probeRecorder) record(phase string, resp *http.Response, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, seen := r.byPhase[phase]; seen {
		prev.Extra++
		r.byPhase[phase] = prev
		return
	}
	pr := ProbeResponse{Phase: phase}
	if err == nil && resp != nil {
		pr.Status = resp.StatusCode
		pr.WWWAuth = resp.Header.Get("WWW-Authenticate") != ""
	}
	r.byPhase[phase] = pr
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
