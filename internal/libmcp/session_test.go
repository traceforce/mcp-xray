package libmcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	old := connectTimeout
	t.Cleanup(func() { connectTimeout = old })
	connectTimeout = 200 * time.Millisecond
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	server.AddTool(&mcp.Tool{Name: "t", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	ts := httptest.NewServer(mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(ts.Close)

	sse := "sse"
	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, Type: &sse, NonInteractive: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	time.Sleep(2 * connectTimeout)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHeaderTransport_MatchesHostWithoutCaseButWithPort(t *testing.T) {
	var got http.Header
	ht := &headerTransport{headers: map[string]string{"Authorization": "Bearer x"}, scheme: "https", host: "MCP.Example:8443",
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
	_, err = ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://σ.EXAMPLE:8443/mcp", nil))
	require.NoError(t, err)
	assert.Equal(t, "Bearer x", got.Get("Authorization"))
	_, err = ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://ς.example:8443/mcp", nil))
	require.NoError(t, err)
	assert.Empty(t, got.Get("Authorization"), "a Unicode spelling must match as written")
}

func TestHeaderTransport_OtherOriginGetsNoCredentialOrReferer(t *testing.T) {
	var got http.Header
	headers := map[string]string{"Authorization": "Bearer x", "User-Agent": "custom/1"}
	ht := &headerTransport{headers: headers, scheme: "https", host: "mcp.example",
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r.Header
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})}
	// Same host over plain http: no bearer in cleartext, no Referer with the configured URL.
	req := httptest.NewRequest(http.MethodPost, "http://mcp.example/mcp", nil)
	req.Header.Set("Referer", "https://mcp.example/mcp?api_key=K")
	_, err := ht.RoundTrip(req)
	require.NoError(t, err)
	assert.Empty(t, got.Get("Authorization"))
	assert.Empty(t, got.Get("Referer"))
	assert.Equal(t, "custom/1", got.Get("User-Agent"), "a configured User-Agent goes everywhere")
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
			assert.Equal(t, "Bearer secret-0123456789", r.Header.Get("Authorization"), r.URL.Path)
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

func TestHeaderTransport_UpgradeKeepsAndNonCredentialCannotExplain401(t *testing.T) {
	var got http.Header
	status := http.StatusOK
	ht := &headerTransport{headers: map[string]string{"Authorization": "Bearer x"}, scheme: "http", host: "mcp.example",
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r.Header
			return &http.Response{StatusCode: status, Body: http.NoBody}, nil
		})}
	_, err := ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil))
	require.NoError(t, err)
	assert.Equal(t, "Bearer x", got.Get("Authorization"), "a same-host upgrade to https keeps the bearer")

	status = http.StatusUnauthorized
	_, err = ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://other.example/mcp", nil))
	assert.ErrorContains(t, err, "sent only to http://mcp.example", "a withheld bearer explains the 401")
	ht.headers = map[string]string{"X-Client-Name": "scanner"}
	resp, err := ht.RoundTrip(httptest.NewRequest(http.MethodPost, "https://other.example/mcp", nil))
	require.NoError(t, err, "withholding a non-credential header cannot explain a 401")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestNewSDKSession_WithheldBearerReadsAsRedirectNotAuth(t *testing.T) {
	// The redirect target 401s; because the bearer was withheld there, the
	// outcome must point at the redirect and not read as a missing credential.
	// Only POST is redirected, so the SDK's cleanup DELETE reaches the configured
	// origin last and must not change the verdict.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(other.Close)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(ts.Close)

	_, err := NewSDKSession(context.Background(), MCPServerConfig{
		Name: "s", URL: &ts.URL, Headers: map[string]string{"Authorization": "Bearer secret-0123456789"}, NonInteractive: true,
	})
	require.Error(t, err)
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), "a withheld-bearer 401 is a redirect, not auth_required")
	assert.Contains(t, err.Error(), "credentials are sent only to", err.Error())
	assert.NotContains(t, err.Error(), "secret-0123456789")
}

func TestNewSDKSession_WithheldBearerOnToolsListIsNotAuth(t *testing.T) {
	// The other host serves initialize without auth but 401s tools/list: the
	// bearer was withheld on purpose, so listing must not read as auth_required.
	inner := jsonrpcServer(t, func(int) string { return "" })
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"tools/list"`) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(other.Close)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(ts.Close)

	s, err := NewSDKSession(context.Background(), MCPServerConfig{
		Name: "s", URL: &ts.URL, Headers: map[string]string{"Authorization": "Bearer secret-0123456789"}, NonInteractive: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	_, err = ListAllTools(context.Background(), s.Session)
	require.Error(t, err)
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), err.Error())
}

func TestNewSDKSession_RedirectBackToConfiguredOriginStaysStripped(t *testing.T) {
	// A→B→A: once the chain leaves A, the bearer is not sent again, even back at
	// A on a URL that B chose, as Go's redirect policy does. A's 401 there is then
	// credential-free and reads as failed, not auth.
	var a *httptest.Server
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"), "the other host must not get the bearer")
		http.Redirect(w, r, a.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(other.Close)
	a = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, other.URL+"/hop", http.StatusTemporaryRedirect)
			return
		}
		assert.Empty(t, r.Header.Get("Authorization"), "the return hop is one B chose")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(a.Close)

	start := a.URL + "/start"
	_, err := NewSDKSession(context.Background(), MCPServerConfig{
		Name: "s", URL: &start, Headers: map[string]string{"Authorization": "Bearer secret-0123456789"}, NonInteractive: true,
	})
	require.Error(t, err)
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), err.Error())
}
