package libmcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewAnonymousSDKSession(t *testing.T) {
	var withToken, hits atomic.Int32
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	h := auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
	}, nil)(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			withToken.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	cfg := MCPServerConfig{Name: "s", URL: &ts.URL, Headers: map[string]string{"Authorization": "Bearer good"}}
	_, status, err := NewAnonymousSDKSession(context.Background(), cfg)
	if err == nil || status() != http.StatusUnauthorized || withToken.Load() != 0 {
		t.Fatalf("err %v, status %d, requests with a token %d; want a 401 and no token sent", err, status(), withToken.Load())
	}
	cmd, before := "server", hits.Load()
	query, userinfo := ts.URL+"?api_key=good", strings.Replace(ts.URL, "http://", "http://u:p@", 1)
	for _, c := range []MCPServerConfig{{Name: "stdio", Command: &cmd}, {Name: "query", URL: &query}, {Name: "userinfo", URL: &userinfo}} {
		if _, _, err := NewAnonymousSDKSession(context.Background(), c); err == nil {
			t.Errorf("%s: connected, want a refusal", c.Name)
		}
	}
	if hits.Load() != before {
		t.Errorf("a refused config still reached the server")
	}
}

func TestStatusTransportKeepsTheCallStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(ts.Close)
	st := &statusTransport{base: http.DefaultTransport}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req, _ := http.NewRequest(method, ts.URL, nil)
		resp, err := (&http.Client{Transport: st}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if got := st.status.Load(); got != http.StatusOK {
		t.Fatalf("status = %d, want the POST's 200; a background GET must not replace it", got)
	}
}
