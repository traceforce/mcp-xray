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
