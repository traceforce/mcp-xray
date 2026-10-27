package libmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	metadata "mcpxray/internal/metadata"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuthConfig_UserAgent(t *testing.T) {
	var seen atomic.Value // User-Agent of the request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.UserAgent())
	}))
	t.Cleanup(ts.Close)

	resp, err := NewOAuthConfig(ts.URL, "", "", "").httpClient.Get(ts.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, metadata.Name+"/"+metadata.Version, seen.Load())
}

func TestNewSDKSession_SSEOutlivesConnectTimeout(t *testing.T) {
	const timeout = 200 * time.Millisecond
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	server.AddTool(&mcp.Tool{Name: "t", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	ts := httptest.NewServer(mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(ts.Close)

	sse := "sse"
	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, Type: &sse, NonInteractive: true, ConnectTimeout: timeout})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	time.Sleep(2 * timeout)
	tools, err := ListAllTools(context.Background(), s.Session)
	require.NoError(t, err)
	assert.Len(t, tools, 1)
}

func TestNewSDKSession_UserAgent(t *testing.T) {
	for _, tc := range []struct {
		headers map[string]string
		want    string
	}{
		{nil, metadata.Name + "/" + metadata.Version},
		{map[string]string{"User-Agent": "custom/1"}, "custom/1"},
	} {
		inner := jsonrpcServer(t, func(int) string { return "" })
		var seen atomic.Value // User-Agent of the last request
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.Store(r.UserAgent())
			inner.Config.Handler.ServeHTTP(w, r)
		}))
		t.Cleanup(ts.Close)

		s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, Headers: tc.headers, NonInteractive: true})
		require.NoError(t, err)
		_ = s.Close()
		assert.Equal(t, tc.want, seen.Load())
	}
}
