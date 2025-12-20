package libmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	metadata "mcpxray/internal/metadata"
	"mcpxray/proto"

	"github.com/cenkalti/backoff/v4"
)

type MCPSession interface {
	SendRequest(ctx context.Context, req MCPRequest) (*MCPResponse, error)
	Close() error
}

// MCPSession represents an HTTP MCP session
type MCPHttpSession struct {
	client    *http.Client
	sessionID string
	url       string
	headers   map[string]string
	mu        sync.Mutex // protects sessionID
}

var _ MCPSession = (MCPSession)(nil)

// MCPStdioSession represents a STDIO MCP session
type MCPStdioSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	encoder *json.Encoder
	decoder *json.Decoder
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
}

// MCPRequest represents a JSON-RPC request to an MCP server
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// MCPResponse represents a JSON-RPC response from an MCP server
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// MCPError represents an error in an MCP response
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	MCPTimeout         = 5 * time.Second
	MCPProtocolVersion = "2025-06-18"
	MCPJSONRPCVersion  = "2.0"
)

var (
	requestIDCounter int64
	httpSessions     sync.Map // url + headers -> *MCPSession
)

var _ MCPSession = (MCPSession)(nil)

func NewMCPSession(ctx context.Context, cfg MCPServerConfig) (MCPSession, error) {
	transport := ClassifyTransport(cfg)
	var session MCPSession
	var err error
	switch transport {
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO:
		session, err = newMCPStdioSession(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return session, nil
	case proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP, proto.MCPTransportType_MCP_TRANSPORT_TYPE_SSE:
		session, err = getOrCreateHTTPSession(*cfg.URL, cfg.Headers)
		if err != nil {
			return nil, err
		}

		// Standard MCP flow: initialize first before we can send any other requests
		initReq := MCPRequest{
			JSONRPC: MCPJSONRPCVersion,
			Method:  "initialize",
			Params: map[string]interface{}{
				"protocolVersion": MCPProtocolVersion,
				"capabilities":    map[string]interface{}{},
				"clientInfo": map[string]string{
					"name":    metadata.Name,
					"version": metadata.Version,
				},
			},
			ID: int(atomic.AddInt64(&requestIDCounter, 1)),
		}

		initResp, err := session.SendRequest(ctx, initReq)
		if err != nil || initResp.Error != nil {
			return nil, fmt.Errorf("failed to initialize session: %w", err)
		}
		return session, nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %v", transport)
	}
}

// newMCPSession creates a new MCP HTTP session
func newMCPHttpSession(url string, headers map[string]string) *MCPHttpSession {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	return &MCPHttpSession{
		client: &http.Client{
			Jar:       jar,
			Transport: tr,
		},
		url:     url,
		headers: headers,
	}
}

// httpCacheKey creates cache key for HTTP sessions
func httpCacheKey(url string, headers map[string]string) string {
	return url + "\n" + canonicalizeHeaders(headers)
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

// getOrCreateHTTPSession gets or creates a cached HTTP session
func getOrCreateHTTPSession(url string, headers map[string]string) (*MCPHttpSession, error) {
	// Initialize headers map if nil to avoid panics
	if headers == nil {
		headers = make(map[string]string)
	}

	key := httpCacheKey(url, headers)
	if v, ok := httpSessions.Load(key); ok {
		return v.(*MCPHttpSession), nil
	}

	// If the headers do not contain an access token, discover it and add it to the headers
	if !hasAccessToken(headers) {
		oauthConfig := NewOAuthConfig(url)
		accessToken, err := oauthConfig.OauthDiscovery()
		if err == nil && accessToken != "" {
			headers["Authorization"] = "Bearer " + accessToken
		}
		// If we cannot discover the access token, just continue with the existing headers
		// the the server might not require authentication
	}
	s := newMCPHttpSession(url, headers)
	actual, _ := httpSessions.LoadOrStore(key, s)
	return actual.(*MCPHttpSession), nil
}

// canonicalizeHeaders creates canonical string of headers
func canonicalizeHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	var b strings.Builder
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, http.CanonicalHeaderKey(k))
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(h[k])
		b.WriteByte('\n')
	}
	return b.String()
}

// newMCPStdioSession creates a new STDIO MCP session with retry
func newMCPStdioSession(ctx context.Context, cfg MCPServerConfig) (*MCPStdioSession, error) {
	var session *MCPStdioSession

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = MCPTimeout

	err := backoff.Retry(func() error {
		var err error
		session, err = newMCPStdioSessionOnce(ctx, cfg)
		if err != nil {
			if isStdioRetryable(err) {
				return err
			}
			return backoff.Permanent(err)
		}
		return nil
	}, backoff.WithContext(bo, ctx))

	return session, err
}

// newMCPStdioSessionOnce creates a STDIO session
func newMCPStdioSessionOnce(ctx context.Context, cfg MCPServerConfig) (*MCPStdioSession, error) {
	if cfg.Command == nil {
		return nil, fmt.Errorf("no command specified for STDIO transport")
	}

	fmt.Printf("Starting MCP Stdio Session %+v\n", cfg)

	sessionCtx, cancel := context.WithCancel(ctx)

	// Handle commands that may contain spaces (e.g., "uvx package@version")
	// Split on first space to separate executable from its first argument
	commandStr := strings.TrimSpace(*cfg.Command)
	var executable string
	var commandArgs []string

	parts := strings.Fields(commandStr)
	if len(parts) > 1 {
		executable = parts[0]
		commandArgs = append(parts[1:], cfg.Args...)
	} else {
		executable = commandStr
		commandArgs = cfg.Args
	}

	// Run command as the user from UserAccount if provided
	var cmd *exec.Cmd
	cmd = exec.CommandContext(sessionCtx, executable, commandArgs...)

	// Set environment variables from the config
	cmd.Env = os.Environ()
	if cfg.Env != nil {
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Set up pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Capture stderr to help diagnose process failures
	stderrBuf := &bytes.Buffer{}
	cmd.Stderr = stderrBuf

	// Start the process
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	br := bufio.NewReaderSize(stdout, 10*1024*1024)
	encoder := json.NewEncoder(stdin)
	decoder := json.NewDecoder(br)

	session := &MCPStdioSession{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		encoder: encoder,
		decoder: decoder,
		ctx:     sessionCtx,
		cancel:  cancel,
	}

	if err := session.initialize(); err != nil {
		session.Close()
		// Include stderr if available to help diagnose EOF issues
		if stderrBuf.Len() > 0 {
			return nil, fmt.Errorf("failed to initialize MCP session: %w (stderr: %s)", err, stderrBuf.String())
		}
		return nil, fmt.Errorf("failed to initialize MCP session: %w", err)
	}

	fmt.Printf("MCP Stdio Session initialized %+v\n", session)

	return session, nil
}

// initialize sends the initialize request to the MCP server
func (s *MCPStdioSession) initialize() error {
	initReq := MCPRequest{
		JSONRPC: MCPJSONRPCVersion,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": MCPProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    metadata.Name,
				"version": metadata.Version,
			},
		},
		ID: int(atomic.AddInt64(&requestIDCounter, 1)),
	}

	if err := s.encoder.Encode(initReq); err != nil {
		return fmt.Errorf("failed to send initialize request: %w", err)
	}

	var initResp MCPResponse
	if err := s.decoder.Decode(&initResp); err != nil {
		return fmt.Errorf("failed to parse initialize response: %w", err)
	}

	if initResp.Error != nil {
		return fmt.Errorf("initialize failed: %s", initResp.Error.Message)
	}

	return nil
}

// sendRequest sends a request through the STDIO session
func (s *MCPStdioSession) SendRequest(_ context.Context, req MCPRequest) (*MCPResponse, error) {
	s.mu.Lock()
	req.ID = int(atomic.AddInt64(&requestIDCounter, 1))
	defer s.mu.Unlock()

	if s.closed {
		return nil, fmt.Errorf("session is closed")
	}

	if err := s.encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var resp MCPResponse
	if err := s.decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// Close closes the STDIO session
func (s *MCPStdioSession) Close() error {
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer timeoutCancel()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	_ = s.stdin.Close()

	done := make(chan struct{})
	go func() {
		_ = s.cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-s.ctx.Done():
		_ = s.cmd.Process.Kill()
		<-done
	case <-timeoutCtx.Done():
		_ = s.cmd.Process.Kill()
		<-done
	}

	s.cancel()
	return nil
}

// SendRequest sends an MCP request and manages session state with simple retry
func (s *MCPHttpSession) SendRequest(ctx context.Context, req MCPRequest) (*MCPResponse, error) {
	var resp *MCPResponse

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = MCPTimeout

	err := backoff.Retry(func() error {
		var err error
		resp, err = s.sendRequestOnce(ctx, req)
		if err != nil {
			if isHTTPRetryable(err) {
				return err
			}
			return backoff.Permanent(err)
		}
		return nil
	}, backoff.WithContext(bo, ctx))

	return resp, err
}

// sendRequestOnce performs a single HTTP request attempt
func (s *MCPHttpSession) sendRequestOnce(ctx context.Context, req MCPRequest) (*MCPResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set standard headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Add configured headers
	for k, v := range s.headers {
		httpReq.Header.Set(k, v)
	}

	s.mu.Lock()
	if s.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	s.mu.Unlock()

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s failed: %w", s.url, err)
	}
	defer resp.Body.Close()

	if sessionID := resp.Header.Get("Mcp-Session-Id"); sessionID != "" {
		s.mu.Lock()
		s.sessionID = sessionID
		s.mu.Unlock()
	}

	// Check status code first, before content-type handling
	if resp.StatusCode >= 400 {
		// Read body for error details
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			bodyBytes = []byte(fmt.Sprintf("(failed to read body: %v)", err))
		}

		err = fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(bodyBytes))

		// Evict from cache on auth failures to prevent bad tokens from being cached
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			cacheKey := httpCacheKey(s.url, s.headers)
			httpSessions.Delete(cacheKey)
		}

		// Wrap with status code info for retry logic
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Err: err}
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return parseSSEResponse(ctx, resp.Body)
	}

	// Read body for JSON response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle regular JSON response
	var mcpResp MCPResponse
	if err := json.Unmarshal(bodyBytes, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(bodyBytes))
	}

	return &mcpResp, nil
}

// HTTPStatusError wraps HTTP errors with status code information
type HTTPStatusError struct {
	StatusCode int
	Err        error
}

func (e *HTTPStatusError) Error() string {
	return e.Err.Error()
}

func (e *HTTPStatusError) Unwrap() error {
	return e.Err
}

// isHTTPRetryable determines if an HTTP error should be retried using proper error types
func isHTTPRetryable(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for HTTP status code errors
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusTooManyRequests, 500, 502, 503, 504:
			return true // Retry on rate limiting and server errors
		default:
			return false // Don't retry client errors (4xx) or other status codes
		}
	}

	// Check for network errors that support Temporary() or Timeout()
	var nerr net.Error
	if errors.As(err, &nerr) && (nerr.Temporary() || nerr.Timeout()) {
		return true
	}

	// Most transport/dial failures are retryable (conservative approach)
	return true
}

// isStdioRetryable determines if a STDIO process error should be retried
func isStdioRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Context cancellation/timeout = not retryable
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	// Command not found or not executable = permanent
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return false
	}

	// Command ran but failed = permanent for MCP servers
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false
	}

	// System-level errors
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errno, ok := pathErr.Err.(syscall.Errno); ok {
			switch errno {
			case syscall.ENOENT, syscall.EACCES: // Not found, permission denied
				return false
			case syscall.EMFILE, syscall.ENFILE: // Too many open files
				return true
			case syscall.EAGAIN: // Resource temporarily unavailable
				return true
			}
		}
		return false
	}

	// Default: assume permanent
	return false
}

// parseSSEResponse parses Server-Sent Events response
func parseSSEResponse(ctx context.Context, body io.Reader) (*MCPResponse, error) {
	scanner := bufio.NewScanner(body)
	// Increase buffer size for large JSON responses (default is 64KB)
	buf := make([]byte, 1024*1024) // 1MB buffer
	scanner.Buffer(buf, 1024*1024)

	var data []byte
	for scanner.Scan() {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			dataLine := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if dataLine != "" {
				if len(data) > 0 {
					data = append(data, '\n')
				}
				data = append(data, []byte(dataLine)...)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading SSE response: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data in SSE response")
	}

	var mcpResp MCPResponse
	if err := json.Unmarshal(data, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to parse SSE data: %w", err)
	}

	return &mcpResp, nil
}

func (s *MCPHttpSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client.CloseIdleConnections()
	return nil
}
