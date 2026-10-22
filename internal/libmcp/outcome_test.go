package libmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkServer serves an SDK MCP server with the given tools, one tool per page.
func sdkServer(t *testing.T, names ...string) *httptest.Server {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ServerOptions{PageSize: 1})
	for _, name := range names {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{}, nil
			})
	}
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(ts.Close)
	return ts
}

// jsonrpcServer answers initialize and returns one tools/list page per call,
// with the nextCursor that next picks for that call number.
func jsonrpcServer(t *testing.T, next func(call int) string) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result := map[string]any{}
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "test", "version": "0"},
			}
		case "tools/list":
			result = map[string]any{
				"tools":      []any{map[string]any{"name": "t", "inputSchema": map[string]any{"type": "object"}}},
				"nextCursor": next(int(calls.Add(1))),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(ts.Close)
	return ts
}

// unauthorizedServer answers 401 to everything and reports whether OAuth discovery was attempted.
func unauthorizedServer(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var discovery atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			discovery.Store(true)
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)
	return ts, &discovery
}

func connect(t *testing.T, url string, nonInteractive bool) (*SDKSession, error) {
	t.Helper()
	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &url, NonInteractive: nonInteractive})
	if err == nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func TestListAllTools_DrainsPages(t *testing.T) {
	ts := sdkServer(t, "a", "b", "c")
	s, err := connect(t, ts.URL, true)
	require.NoError(t, err)

	tools, err := ListAllTools(context.Background(), s.Session)
	require.NoError(t, err)
	var names []string
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	assert.Equal(t, []string{"a", "b", "c"}, names)
}

func TestListAllTools_RepeatedCursor(t *testing.T) {
	ts := jsonrpcServer(t, func(int) string { return "same" })
	s, err := connect(t, ts.URL, true)
	require.NoError(t, err)

	tools, err := ListAllTools(context.Background(), s.Session)
	assert.Nil(t, tools)
	assert.ErrorContains(t, err, "repeated cursor")
}

func TestListAllTools_PageLimit(t *testing.T) {
	var pages atomic.Int32
	ts := jsonrpcServer(t, func(call int) string { pages.Store(int32(call)); return fmt.Sprint(call) })
	s, err := connect(t, ts.URL, true)
	require.NoError(t, err)

	tools, err := ListAllTools(context.Background(), s.Session)
	assert.Nil(t, tools)
	assert.ErrorContains(t, err, "did not end")
	assert.EqualValues(t, maxToolPages, pages.Load())
}

func TestNewSDKSession_NonInteractiveReportsAuthRequired(t *testing.T) {
	ts, discovery := unauthorizedServer(t)
	_, err := connect(t, ts.URL, true)
	require.Error(t, err)
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(err))
	assert.False(t, discovery.Load(), "non-interactive must not run OAuth discovery")
}

func TestNewSDKSession_InteractiveRunsDiscovery(t *testing.T) {
	ts, discovery := unauthorizedServer(t)
	_, err := connect(t, ts.URL, false)
	require.Error(t, err)
	assert.True(t, discovery.Load())
}

func TestOutcomeForError_Unlaunchable(t *testing.T) {
	cmd := "mcpxray-no-such-binary-0b1e"
	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", Command: &cmd})
	require.Error(t, err)
	assert.Equal(t, OutcomeUnlaunchable, OutcomeForError(err))
}

func TestOutcomeForError(t *testing.T) {
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(&DCRUnauthorizedError{ServerName: "s"}))
	assert.Equal(t, OutcomeUnlaunchable, OutcomeForError(&fs.PathError{Op: "fork/exec", Path: "/no/such/server", Err: fs.ErrNotExist}))
	assert.Equal(t, OutcomeUnlaunchable, OutcomeForError(&fs.PathError{Op: "fork/exec", Path: "/srv/server", Err: fs.ErrPermission}))
	assert.Equal(t, OutcomeUnlaunchable, OutcomeForError(&fs.PathError{Op: "fork/exec", Path: "/srv/server", Err: errors.New("exec format error")}))
	assert.Equal(t, OutcomeFailed, OutcomeForError(&fs.PathError{Op: "open", Path: "/srv/config", Err: fs.ErrNotExist}))
	assert.Equal(t, OutcomeFailed, OutcomeForError(errors.New("boom")))
}

func TestServerOutcome_JSON(t *testing.T) {
	got, err := json.Marshal(ServerOutcome{Server: "s", Status: OutcomeAuthRequired, Reason: "Unauthorized"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"server":"s","status":"auth_required","reason":"Unauthorized","tool_count":0}`, string(got))

	got, err = json.Marshal(ServerOutcome{Server: "s", Status: OutcomeEmpty})
	require.NoError(t, err)
	assert.JSONEq(t, `{"server":"s","status":"empty","tool_count":0}`, string(got))
}
