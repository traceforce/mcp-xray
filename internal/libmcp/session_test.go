package libmcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	metadata "mcpxray/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHeaderTransport_MatchesHostWithoutCaseButWithPort(t *testing.T) {
	var got http.Header
	ht := &headerTransport{headers: map[string]string{"Authorization": "Bearer x"}, host: "MCP.Example:8443",
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r.Header
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})}
	for _, u := range []string{"https://mcp.example:8443/mcp", "https://MCP.EXAMPLE:8443/mcp"} {
		_, err := ht.RoundTrip(httptest.NewRequest(http.MethodPost, u, nil))
		require.NoError(t, err)
		assert.Equal(t, "Bearer x", got.Get("Authorization"), u)
	}
	_, err := ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://mcp.example:9443/mcp", nil))
	require.NoError(t, err)
	assert.Empty(t, got.Get("Authorization"), "another port is another host")
	// Only ASCII folds: σ and ς fold alike yet encode to different names.
	ht.host = "σ.example:8443"
	_, err = ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://σ.example:8443/mcp", nil))
	require.NoError(t, err)
	assert.Equal(t, "Bearer x", got.Get("Authorization"))
	_, err = ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://ς.example:8443/mcp", nil))
	require.NoError(t, err)
	assert.Empty(t, got.Get("Authorization"), "a Unicode spelling must match as written")
}

func TestNewSDKSession_SendsHeadersToConfiguredHostOnly(t *testing.T) {
	var asked atomic.Int32 // requests the other host received, each checked for the bearer
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		assert.Empty(t, r.Header.Get("Authorization"), "the other host must not get the bearer")
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(other.Close)
	inner := jsonrpcServer(t, func(int) string { return "" })
	// /same redirects within the host, /away to the other host, and /sse names
	// the other host in its endpoint event.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/mcp", http.StatusTemporaryRedirect)
		case "/away":
			http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: endpoint\ndata: %s/messages\n\n", other.URL)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			inner.Config.Handler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	headers := map[string]string{"Authorization": "Bearer secret-0123456789"}

	same := ts.URL + "/same"
	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &same, Headers: headers, NonInteractive: true})
	require.NoError(t, err)
	_ = s.Close()

	for _, path := range []string{"/away", "/sse"} {
		away := ts.URL + path
		_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &away, Headers: headers, NonInteractive: true})
		require.Error(t, err, path)
		assert.Positive(t, asked.Swap(0), path)
		assert.Equal(t, OutcomeFailed, OutcomeForError(err), path)
	}
}
