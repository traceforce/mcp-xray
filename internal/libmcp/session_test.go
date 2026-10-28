package libmcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func strptr(s string) *string { return &s }

// captureRT records the bodies it receives and answers with its status.
type captureRT struct {
	status int
	bodies []string
}

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		c.bodies = append(c.bodies, string(b))
	}
	return &http.Response{StatusCode: c.status, Header: http.Header{"Www-Authenticate": {"Bearer"}}, Body: http.NoBody}, nil
}

func post(t *testing.T, rec *probeRecorder, method string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"id":1,"method":"`+method+`"}`))
	resp, err := rec.RoundTrip(req)
	if err != nil {
		t.Fatalf("roundtrip %s: %v", method, err)
	}
	resp.Body.Close()
}

func TestProbeRecorder(t *testing.T) {
	t.Run("records phases", func(t *testing.T) {
		base := &captureRT{status: 401}
		rec := &probeRecorder{base: base, byPhase: map[string]ProbeResponse{}}
		post(t, rec, "initialize")
		post(t, rec, "notifications/initialized") // ignored
		post(t, rec, "tools/call")
		post(t, rec, "tools/call") // second -> Extra
		g, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
		gr, _ := rec.RoundTrip(g) // GET ignored when sse=false
		gr.Body.Close()

		if pr, ok := rec.byPhase["initialize"]; !ok || pr.Status != 401 || !pr.WWWAuth {
			t.Errorf("initialize = %+v ok=%v", pr, ok)
		}
		if got := rec.byPhase["tools/call"].Extra; got != 1 || len(rec.byPhase) != 2 {
			t.Errorf("extra=%d phases=%d, want 1 and 2", got, len(rec.byPhase))
		}
		if len(base.bodies) == 0 || !strings.Contains(base.bodies[0], `"method":"initialize"`) {
			t.Errorf("base did not see restored body: %v", base.bodies)
		}
	})

	t.Run("refuses a credential", func(t *testing.T) {
		for _, set := range []func(*http.Request){
			func(r *http.Request) { r.SetBasicAuth("u", "p") },
			func(r *http.Request) { r.URL.User = url.UserPassword("u", "p") },
		} {
			base := &captureRT{status: 200}
			rec := &probeRecorder{base: base, byPhase: map[string]ProbeResponse{}}
			req, _ := http.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"id":1,"method":"initialize"}`))
			set(req)
			if _, err := rec.RoundTrip(req); !errors.Is(err, ErrUnsupportedCredentialPath) || len(base.bodies) != 0 {
				t.Errorf("err = %v, base saw %d requests; want the request refused", err, len(base.bodies))
			}
		}
	})

	t.Run("skips a redirect hop", func(t *testing.T) {
		rec := &probeRecorder{base: &captureRT{status: http.StatusTemporaryRedirect}, byPhase: map[string]ProbeResponse{}}
		post(t, rec, "tools/call")
		if len(rec.byPhase) != 0 {
			t.Errorf("a 3xx hop was recorded: %+v", rec.byPhase)
		}
	})
}

func TestNewUnauthenticatedSDKSessionRefuses(t *testing.T) {
	tests := []struct {
		name string
		cfg  MCPServerConfig
	}{
		{"stdio", MCPServerConfig{Name: "s", Command: strptr("proxy")}},
		{"x-api-key", MCPServerConfig{Name: "s", URL: strptr("https://x.example"), Headers: map[string]string{"X-API-Key": "k"}}},
		{"userinfo", MCPServerConfig{Name: "s", URL: strptr("https://user:pw@x.example")}},
		{"query", MCPServerConfig{Name: "s", URL: strptr("https://x.example?token=abc")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewUnauthenticatedSDKSession(context.Background(), tt.cfg); !errors.Is(err, ErrUnsupportedCredentialPath) {
				t.Fatalf("err = %v, want ErrUnsupportedCredentialPath", err)
			}
		})
	}
}

// testServer starts an in-process MCP server (streamable or SSE), optionally behind
// bearer auth, and counts hits to the OAuth discovery endpoints.
func testServer(t *testing.T, withAuth, sse bool) (url string, oauthHits func() int) {
	t.Helper()
	var hits atomic.Int32
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	get := func(*http.Request) *mcp.Server { return srv }
	var h http.Handler = mcp.NewStreamableHTTPHandler(get, nil)
	path := "/"
	if sse {
		h, path = mcp.NewSSEHandler(get, nil), "/sse"
	}
	if withAuth {
		h = auth.RequireBearerToken(
			func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
				if token == "good" {
					return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
				}
				return nil, auth.ErrInvalidToken
			},
			&auth.RequireBearerTokenOptions{ResourceMetadataURL: "https://as.example/.well-known/oauth-protected-resource"},
		)(h)
	}
	count := func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.NotFound(w, r) }
	mux := http.NewServeMux()
	for _, p := range []string{"/.well-known/", "/register", "/authorize", "/token"} {
		mux.HandleFunc(p, count)
	}
	mux.Handle(path, h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + path, func() int { return int(hits.Load()) }
}

func TestUnauthenticatedProbeStreamableRejected(t *testing.T) {
	url, oauthHits := testServer(t, true, false)
	headers := map[string]string{"Authorization": "Bearer good"}
	_, err := NewUnauthenticatedSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &url, Headers: headers})
	var pe *ProbeError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ProbeError", err)
	}
	if pe.Response.Status != 401 || pe.Response.Phase != "initialize" || !pe.Response.WWWAuth {
		t.Errorf("probe = %+v, want 401/initialize/WWWAuth", pe.Response)
	}
	if oauthHits() != 0 {
		t.Errorf("OAuth endpoints hit %d times, want 0", oauthHits())
	}
	if _, ok := headers["Authorization"]; !ok {
		t.Error("caller's Authorization header was removed")
	}
}

func TestUnauthenticatedProbeStreamableConnects(t *testing.T) {
	url, _ := testServer(t, false, false)
	sess, err := NewUnauthenticatedSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &url})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()
	if pr, ok := sess.Probe("initialize"); !ok || pr.Status != 200 {
		t.Errorf("probe initialize = %+v ok=%v, want 200", pr, ok)
	}
}

func TestUnauthenticatedProbeRefusesRedirectUserinfo(t *testing.T) {
	var credentialed atomic.Int32
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse(ts.URL + "/real")
		u.User = url.UserPassword("u", "p")
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/real", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			credentialed.Add(1)
		}
	})
	u := ts.URL + "/mcp"
	if _, err := NewUnauthenticatedSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &u}); err == nil {
		t.Fatal("connected through a redirect that carries a credential")
	}
	if n := credentialed.Load(); n != 0 {
		t.Errorf("%d requests carried a credential", n)
	}
}

func TestUnauthenticatedProbeSSERejected(t *testing.T) {
	url, _ := testServer(t, true, true)
	_, err := NewUnauthenticatedSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &url})
	var pe *ProbeError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ProbeError", err)
	}
	if pe.Response.Phase != "sse_connect" || pe.Response.Status != 401 {
		t.Errorf("probe = %+v, want sse_connect/401", pe.Response)
	}
}
