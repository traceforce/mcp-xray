package configscan

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

	"SecureMCP/internal/build"
	"SecureMCP/internal/config_parser"

	"github.com/cenkalti/backoff/v4"
)

// MCPSession represents an HTTP MCP session
type MCPSession struct {
	client    *http.Client
	sessionID string
	url       string
	headers   map[string]string
	mu        sync.Mutex // protects sessionID
}

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

// newMCPSession creates a new MCP HTTP session
func newMCPSession(url string, headers map[string]string) *MCPSession {
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
	return &MCPSession{
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

// getOrCreateHTTPSession gets or creates a cached HTTP session
func getOrCreateHTTPSession(url string, headers map[string]string) *MCPSession {
	key := httpCacheKey(url, headers)
	if v, ok := httpSessions.Load(key); ok {
		return v.(*MCPSession)
	}
	s := newMCPSession(url, headers)
	actual, _ := httpSessions.LoadOrStore(key, s)
	return actual.(*MCPSession)
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
func newMCPStdioSession(ctx context.Context, cfg config_parser.MCPServerConfig, userAccount *UserAccount) (*MCPStdioSession, error) {
	var session *MCPStdioSession

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = MCPTimeout

	err := backoff.Retry(func() error {
		var err error
		session, err = newMCPStdioSessionOnce(ctx, cfg, userAccount)
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
func newMCPStdioSessionOnce(ctx context.Context, cfg config_parser.MCPServerConfig, userAccount *UserAccount) (*MCPStdioSession, error) {
	if cfg.Command == nil {
		return nil, fmt.Errorf("no command specified for STDIO transport")
	}

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
	if userAccount != nil && userAccount.Uid != "" {
		// Use username if available, otherwise fall back to UID with # prefix
		userIdentifier := userAccount.Username
		if userIdentifier == "" {
			userIdentifier = "#" + userAccount.Uid
		}

		// Build the full command string to pass to the shell
		// This preserves the original command structure (executable + args)
		allArgs := append([]string{executable}, commandArgs...)
		commandStr := strings.Join(allArgs, " ")

		// Launch an interactive shell as the user and execute the command.
		// Interactive shell ensures the user's environment including PATH is properly set.
		args := []string{"-iu", userIdentifier, "sh", "-lc", commandStr}
		cmd = exec.CommandContext(sessionCtx, "/usr/bin/sudo", args...)
	} else {
		cmd = exec.CommandContext(sessionCtx, executable, commandArgs...)
	}

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
		return nil, fmt.Errorf("failed to initialize MCP session: %w", err)
	}

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
				"name":    build.Name,
				"version": build.Version,
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
func (s *MCPStdioSession) sendRequest(req MCPRequest) (*MCPResponse, error) {
	s.mu.Lock()
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

// sendRequest sends an MCP request and manages session state with simple retry
func (s *MCPSession) sendRequest(ctx context.Context, req MCPRequest) (*MCPResponse, error) {
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
func (s *MCPSession) sendRequestOnce(ctx context.Context, req MCPRequest) (*MCPResponse, error) {
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
