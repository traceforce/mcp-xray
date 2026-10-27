package libmcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustTokenServer makes tokenClient trust a TLS test server for the test.
func trustTokenServer(t *testing.T, ts *httptest.Server) {
	t.Helper()
	saved := tokenClient.Transport
	tokenClient.Transport = ts.Client().Transport
	t.Cleanup(func() { tokenClient.Transport = saved })
}

// tokenServer is a TLS token endpoint answering with reply; it records the last form it received.
func tokenServer(t *testing.T, status int, reply map[string]string) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var form atomic.Value
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form.Store(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(ts.Close)
	trustTokenServer(t, ts)
	return ts, &form
}

// bearerServer is a TLS MCP server for requests carrying want, and 401 to the
// rest; the session's transport trusts it for the test.
func bearerServer(t *testing.T, want string) *httptest.Server {
	t.Helper()
	inner := jsonrpcServer(t, func(int) string { return "" })
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	trustMCPServer(t, ts)
	return ts
}

// trustMCPServer makes the session's transport trust a TLS test server for the test.
func trustMCPServer(t *testing.T, ts *httptest.Server) {
	t.Helper()
	saved := http.DefaultTransport
	http.DefaultTransport = ts.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = saved })
}

func TestNewSDKSession_StoredCredentialKeepsRotatedToken(t *testing.T) {
	tok, form := tokenServer(t, http.StatusOK, map[string]string{"access_token": "access-2", "refresh_token": "refresh-2", "token_type": "Bearer"})
	ts := bearerServer(t, "Bearer access-2")
	creds := Credentials{ts.URL: {TokenEndpoint: tok.URL + "/token", ClientID: "client-1", RefreshToken: "refresh-1"}}
	path := filepath.Join(t.TempDir(), "creds.json")

	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds, CredentialsFile: path})
	require.NoError(t, err)
	_ = s.Close()
	assert.Equal(t, "refresh-2", creds[ts.URL].RefreshToken)
	saved, err := LoadCredentials(path)
	require.NoError(t, err)
	assert.Equal(t, "refresh-2", saved[ts.URL].RefreshToken, "the rotated token is on disk before the session is used")
	assert.Equal(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {"refresh-1"}, "client_id": {"client-1"}, "resource": {ts.URL},
	}, form.Load())
}

func TestNewSDKSession_RejectedCredentialReportsAuthRequired(t *testing.T) {
	tok, _ := tokenServer(t, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "refresh-secret-1 is revoked"})
	var asked atomic.Bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Store(true) }))
	t.Cleanup(ts.Close)
	trustMCPServer(t, ts) // so asked would record a connection the code wrongly made
	creds := Credentials{ts.URL: {TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "refresh-secret-1"}}

	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds})
	require.Error(t, err)
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(err))
	assert.ErrorContains(t, err, "invalid_grant")
	assert.NotContains(t, err.Error(), "refresh-secret-1", "the token endpoint's body is never reported")
	assert.False(t, asked.Load(), "the server is not tried without a login")

	for _, tc := range []struct {
		status int
		reply  map[string]string
		want   string
	}{
		{http.StatusForbidden, map[string]string{"error": "unauthorized_client"}, OutcomeAuthRequired}, // Atlassian
		{http.StatusOK, map[string]string{"error": "invalid_grant"}, OutcomeAuthRequired},
		{http.StatusOK, map[string]string{"error": "invalid_grant", "access_token": "stale"}, OutcomeAuthRequired},
		{http.StatusUnauthorized, nil, OutcomeAuthRequired},
		{http.StatusBadRequest, map[string]string{"error": "invalid_target"}, OutcomeAuthRequired},
		{http.StatusNotFound, nil, OutcomeAuthRequired},          // gone: a new login rediscovers it
		{http.StatusPermanentRedirect, nil, OutcomeAuthRequired}, // moved for good, likewise
		{http.StatusForbidden, nil, OutcomeFailed},               // a WAF or CDN page, not a refusal
		{http.StatusOK, map[string]string{"error": "temporarily_unavailable"}, OutcomeFailed},
		{http.StatusTemporaryRedirect, nil, OutcomeFailed},
		{http.StatusTooManyRequests, nil, OutcomeFailed},
		{http.StatusServiceUnavailable, nil, OutcomeFailed},
		{http.StatusOK, map[string]string{"error": "invalid_refresh_token"}, OutcomeAuthRequired}, // Slack's non-RFC refusal shape
		{http.StatusOK, map[string]string{"error": "expired_token"}, OutcomeAuthRequired},
		{http.StatusTooManyRequests, map[string]string{"error": "invalid_request"}, OutcomeFailed},  // an RFC code on a 429 is still an outage
		{http.StatusServiceUnavailable, map[string]string{"error": "invalid_grant"}, OutcomeFailed}, // likewise on a 503
	} {
		srv, _ := tokenServer(t, tc.status, tc.reply)
		creds[ts.URL] = Credential{TokenEndpoint: srv.URL, ClientID: "c", RefreshToken: "r"}
		_, err = NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds})
		assert.Equal(t, tc.want, OutcomeForError(err), "%d %v", tc.status, tc.reply)
	}
	tok.Close()
	creds[ts.URL] = Credential{TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r"}
	_, err = NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds})
	require.Error(t, err)
	assert.Equal(t, OutcomeFailed, OutcomeForError(err))
}

func TestCredentialRefresh_RefusesRedirectsAndPlainHTTP(t *testing.T) {
	var asked atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked.Store(true) }))
	t.Cleanup(other.Close)
	tok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(tok.Close)
	trustTokenServer(t, tok)

	cred := Credential{TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r"}
	_, err := cred.refresh("https://mcp.example/mcp")
	assert.ErrorContains(t, err, "307")
	assert.False(t, asked.Load(), "the refresh token must not follow a redirect")

	cred.TokenEndpoint = "http://auth.example/token"
	_, err = cred.refresh("https://mcp.example/mcp")
	assert.ErrorContains(t, err, "https")
}

func TestCredentialRefresh_TransportErrorHidesEncodedToken(t *testing.T) {
	secret := "refresh/secret/1"
	// A malformed Location Go cannot parse, echoing the token URL-encoded; Go's
	// redirect error would carry it before CheckRedirect ever runs.
	tok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://%zz/cb?rt="+url.QueryEscape(secret))
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(tok.Close)
	trustTokenServer(t, tok)

	cred := Credential{TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: secret}
	_, err := cred.refresh("https://mcp.example/mcp")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret, "the raw refresh token must not reach the error")
	assert.NotContains(t, err.Error(), url.QueryEscape(secret), "nor its URL-encoded form")
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), "a transport failure is failed, not a refused credential")
}

func TestCredentialRefresh_PartialDecodeIsFailure(t *testing.T) {
	// A 200 whose refresh_token has the wrong type: the decoder sets access_token
	// then errors. The partial reply must not count as a successful refresh.
	tok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-2","refresh_token":123}`))
	}))
	t.Cleanup(tok.Close)
	trustTokenServer(t, tok)

	cred := Credential{TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r1"}
	access, err := cred.refresh("https://mcp.example/mcp")
	require.Error(t, err)
	assert.Empty(t, access, "a partially decoded response yields no access token")
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), "a malformed success body is a failure, not a refusal")
	assert.Equal(t, "r1", cred.RefreshToken, "the stored refresh token is left unchanged")
	assert.NotContains(t, err.Error(), "123", "no decoder text reaches the error")
}

func TestNewHTTPClient_InteractiveKeepsTransientOutageFailed(t *testing.T) {
	// A transient token-endpoint outage in interactive mode must not fall back to a
	// browser login and end as auth_required; it stays a failure.
	down, _ := tokenServer(t, http.StatusServiceUnavailable, nil)
	u := "https://127.0.0.1:65000/mcp" // same site (127.0.0.1) as the token server, so keepable passes
	creds := Credentials{u: {TokenEndpoint: down.URL, ClientID: "c", RefreshToken: "r"}}
	_, _, err := newHTTPClient(MCPServerConfig{Name: "s", URL: &u, NonInteractive: false, Credentials: creds})
	require.Error(t, err)
	assert.Equal(t, OutcomeFailed, OutcomeForError(err), "a transient outage stays failed, never a browser re-login")
}

func TestExchangeCode_MalformedBodyReturnsConstantError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"`)) // a truncated 200 body the decoder chokes on
	}))
	t.Cleanup(ts.Close)

	o := NewOAuthConfig("https://mcp.example/mcp", "c", "client-secret-xyz", "http://127.0.0.1:8765/callback")
	_, _, err := o.exchangeCode(ts.URL, "c", "client-secret-xyz", "auth-code-xyz", "verifier")
	require.Error(t, err)
	assert.EqualError(t, err, "token exchange failed: 200", "a malformed body yields only the status")
	assert.NotContains(t, err.Error(), "auth-code-xyz", "the authorization code never reaches the error")
	assert.NotContains(t, err.Error(), "client-secret-xyz", "nor the client secret")
}

func TestExchangeCode_LoopbackHTTPAndSameOriginRedirect(t *testing.T) {
	// As at base: a loopback http token endpoint works, and a 307 to /token/ is
	// followed with the form re-posted.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			http.Redirect(w, r, "/token/", http.StatusTemporaryRedirect)
			return
		}
		assert.Equal(t, "code", r.PostFormValue("code"))
		_, _ = w.Write([]byte(`{"access_token":"a"}`))
	}))
	t.Cleanup(ts.Close)
	o := NewOAuthConfig("https://mcp.example/mcp", "c", "s", "http://127.0.0.1:8765/callback")
	tok, endpoint, err := o.exchangeCode(ts.URL+"/token", "c", "s", "code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "a", tok.AccessToken)
	assert.Equal(t, ts.URL+"/token/", endpoint, "a refresh, which follows no redirect, goes where the exchange ended")
}

func TestExchangeCode_MalformedEndpointDoesNotPanic(t *testing.T) {
	// A server-advertised token endpoint that does not parse made http.NewRequest return
	// a nil request, which panicked on the next header set, after the user had consented.
	o := NewOAuthConfig("https://mcp.example/mcp", "c", "s", "http://127.0.0.1:8765/callback")
	for _, ep := range []string{"https://%zz/token", "https://auth example.com/token"} {
		_, _, err := o.exchangeCode(ep, "c", "s", "code", "verifier")
		require.Error(t, err, ep)
		assert.Contains(t, err.Error(), "token exchange failed")
	}
}

func TestExchangeCode_RefusalWithTokenIsReported(t *testing.T) {
	// An RFC error code is a refusal even when the server also returns an access_token,
	// so the exchange failure is reported rather than a stale token used.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant","access_token":"stale"}`))
	}))
	t.Cleanup(ts.Close)
	o := NewOAuthConfig("https://mcp.example/mcp", "c", "s", "http://127.0.0.1:8765/callback")
	_, _, err := o.exchangeCode(ts.URL, "c", "s", "code", "verifier")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestKeepable_PinMatchesByOrigin(t *testing.T) {
	// A pin copied verbatim from the AS metadata still keeps an off-site login when the
	// stored endpoint was redirected (307 to a trailing slash) or had its scheme re-cased.
	c := Credential{TokenEndpoint: "https://login.semgrep.dev/oauth2/token/"}
	assert.True(t, keepable("https://mcp.semgrep.io/mcp", c, "https://login.semgrep.dev/oauth2/token"), "a 307 to /token/ still matches the pin")
	assert.True(t, keepable("https://mcp.semgrep.io/mcp", c, "HTTPS://login.semgrep.dev/oauth2/token"), "an uppercase scheme matches")
	assert.False(t, keepable("https://mcp.semgrep.io/mcp", c, "https://evil.example.com/token"), "a different host is not kept")
	assert.False(t, keepable("https://mcp.semgrep.io/mcp", c, ""), "no pin and off-site is not kept")
}

func TestLoadCredentials_RefusesUnknownField(t *testing.T) {
	// A login entry with a field this version does not know is refused, not loaded and
	// silently dropped on the next Save.
	path := filepath.Join(t.TempDir(), "creds.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"https://mcp.example/mcp":{"token_endpoint":"https://a/t","refresh_token":"r","expires_at":123}}`), 0o600))
	_, err := LoadCredentials(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse credentials file")
}

func TestCredentials_SaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	creds, err := LoadCredentials(path)
	require.NoError(t, err)
	assert.Empty(t, creds, "a missing file is an empty set")
	for _, body := range []string{"", "null"} {
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		creds, err = LoadCredentials(path)
		require.NoError(t, err)
		assert.NotNil(t, creds, "an empty or null file is an empty set that can be added to")
	}
	require.NoError(t, os.WriteFile(path, []byte(`{"mcpServers":{}}`), 0600))
	_, err = LoadCredentials(path)
	assert.ErrorContains(t, err, "is not a stored login", "an empty MCP config is refused, never rewritten")
	require.NoError(t, os.WriteFile(path, []byte(`{"mcpServers":{"s":{"url":"https://mcp.example/mcp"}}}`), 0600))
	_, err = LoadCredentials(path)
	assert.Error(t, err, "an MCP config is refused, not rewritten as credentials")

	creds["https://mcp.example/mcp"] = Credential{TokenEndpoint: "https://auth.example/token", ClientID: "c", RefreshToken: "r"}
	require.NoError(t, creds.Save(path))
	got, err := LoadCredentials(path)
	require.NoError(t, err)
	assert.Equal(t, creds, got)
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		require.NoError(t, os.Chmod(path, 0644))
		_, err = LoadCredentials(path)
		assert.ErrorContains(t, err, "accessible by group or others")
	}
}

func TestKeepable_SameSiteHTTPSOnly(t *testing.T) {
	for _, tc := range []struct {
		mcp, token string
		want       bool
	}{
		{"https://mcp.supabase.com/mcp", "https://api.supabase.com/v1/oauth/token", true},
		{"https://mcp.example.co.uk/mcp", "https://auth.example.co.uk/token", true},
		{"https://mcp.attacker.com/mcp", "https://api.supabase.com/v1/oauth/token", false},
		{"https://a.github.io/mcp", "https://b.github.io/token", false}, // a public suffix is not one owner
		{"http://mcp.supabase.com/mcp", "https://api.supabase.com/token", false},
		{"https://mcp.supabase.com/mcp", "http://api.supabase.com/token", false},
		{"https://192.0.2.10/mcp", "https://198.51.2.10/token", false}, // distinct IPs that share octets are not one site
		{"https://192.0.2.10/mcp", "https://192.0.2.10/token", true},   // the same IP host is one site
	} {
		assert.Equal(t, tc.want, keepable(tc.mcp, Credential{TokenEndpoint: tc.token}, ""), tc)
	}
	// A config can vouch for a token endpoint off the server's site, such as a hosted auth provider.
	hosted := Credential{TokenEndpoint: "https://tenant.authkit.app/oauth2/token"}
	assert.True(t, keepable("https://mcp.vendor.dev/", hosted, hosted.TokenEndpoint))
	assert.False(t, keepable("https://mcp.vendor.dev/", hosted, "https://other.authkit.app/oauth2/token"))
	// An IDN host folds to the punycode the client dials, not a different domain.
	assert.Equal(t, site("xn--mnchen-3ya.com"), site("münchen.com"), "IDN and its punycode are one site")
	// Full-width digits that IDNA folds to an IPv4 literal stay distinct addresses.
	assert.NotEqual(t, site("１９２.０.２.１０"), site("１９８.５１.２.１０"), "full-width IPv4 forms are not one site")
}

func TestNewSDKSession_StoredCredentialFromAnotherSiteIsNotUsed(t *testing.T) {
	var sent atomic.Bool // any token request at all, wherever it would go
	saved := tokenClient.Transport
	tokenClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		sent.Store(true)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"a"}`))}, nil
	})
	t.Cleanup(func() { tokenClient.Transport = saved })
	ts := bearerServer(t, "Bearer a")
	creds := Credentials{ts.URL: {TokenEndpoint: "https://auth.other.example/token", ClientID: "c", RefreshToken: "r"}}
	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds})
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(err))
	assert.False(t, sent.Load(), "the refresh token is not sent to a token endpoint off the server's site")
}

func TestNewSDKSession_StoredCredentialNeedsHTTPS(t *testing.T) {
	tok, form := tokenServer(t, http.StatusOK, map[string]string{"access_token": "a", "refresh_token": "r2"})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)
	creds := Credentials{ts.URL: {TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r1"}}
	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: creds})
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(err))
	assert.Nil(t, form.Load(), "the refresh token is not spent on a server that would get the access token in clear")
	assert.Equal(t, "r1", creds[ts.URL].RefreshToken)
}

func TestWithBearer_ReplacesEverySpellingOfAuthorization(t *testing.T) {
	headers := map[string]string{"authorization": "Basic x", "AUTHORIZATION": "bearer old", "X-Custom": "1"}
	assert.True(t, hasAccessToken(headers), "a bearer counts in any spelling")
	assert.True(t, hasAccessToken(map[string]string{"authorization": "Basic x"}), "so does any configured scheme")
	assert.False(t, hasAccessToken(map[string]string{"Authorization": " "}))
	assert.False(t, hasAccessToken(map[string]string{"Authorization": "${env:MCP_TOKEN}"}), "an unexpanded ${…} placeholder is not a credential")
	assert.False(t, hasAccessToken(map[string]string{"Authorization": "{{TOKEN}}"}), "nor a {{…}} placeholder")
	assert.False(t, hasAccessToken(map[string]string{"Authorization": "Bearer"}), "a bare scheme carries nothing")
	assert.True(t, hasAccessToken(map[string]string{"Authorization": "Bearer real-token"}), "a scheme plus a credential counts")
	assert.Equal(t, map[string]string{"Authorization": "Bearer new", "X-Custom": "1"}, withBearer(headers, "new"))
	assert.Len(t, headers, 3, "the caller's map is left as configured")
}

func TestRedirectServer_IgnoresACallbackForAnotherLogin(t *testing.T) {
	codeCh, errCh := make(chan string, 1), make(chan string, 1)
	shutdown, err := startRedirectServer(codeCh, errCh, "127.0.0.1", 8766, "mine")
	require.NoError(t, err)
	defer shutdown()
	_, err = startRedirectServer(codeCh, errCh, "127.0.0.1", 8766, "mine")
	assert.Error(t, err, "a port held by another listener is an error, before any browser opens")
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}} // shutdown would wait for an idle conn
	for _, q := range []string{"?code=c&state=theirs", "?error=access_denied&state=theirs"} {
		resp, err := client.Get("http://127.0.0.1:8766" + RedirectPath + q)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, q)
	}
	assert.Empty(t, codeCh)
	assert.Empty(t, errCh, "a stray callback must not end the login")

	resp, err := client.Get("http://127.0.0.1:8766" + RedirectPath + "?code=c&state=mine")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "c", <-codeCh)
}

func TestCredentials_SaveKeepsSymlinkAndMergesOtherRuns(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "private.json")
	link := filepath.Join(dir, "creds.json")
	require.NoError(t, Credentials{"x": {TokenEndpoint: "https://a.example/t", RefreshToken: "x1"}, "y": {TokenEndpoint: "https://a.example/t", RefreshToken: "y1"}}.Save(target))
	symlinked := os.Symlink(target, link) == nil // Windows needs a privilege for it
	if !symlinked {
		link = target
	}
	// Another run rotated y after this one loaded the file; this run rotates x.
	mine := Credentials{"x": {TokenEndpoint: "https://a.example/t", RefreshToken: "x2"}, "y": {TokenEndpoint: "https://a.example/t", RefreshToken: "y1"}}
	require.NoError(t, Credentials{"x": {TokenEndpoint: "https://a.example/t", RefreshToken: "x1"}, "y": {TokenEndpoint: "https://a.example/t", RefreshToken: "y2"}}.Save(link))
	MCPServerConfig{Credentials: mine, CredentialsFile: link}.saveCredentials("x")

	if symlinked {
		info, err := os.Lstat(link)
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&os.ModeSymlink, "the link still points at the private file")
	}
	got, err := LoadCredentials(target)
	require.NoError(t, err)
	assert.Equal(t, "x2", got["x"].RefreshToken)
	assert.Equal(t, "y2", got["y"].RefreshToken, "the other run's rotation survives")
	assert.False(t, CredentialsSaveFailed())
}

func TestCredentials_SaveWritesInPlaceWhenRenameIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a directory the test cannot write")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))
	require.NoError(t, os.Chmod(dir, 0500)) // like a single-file bind mount: no temp file beside it
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	require.NoError(t, Credentials{"x": {TokenEndpoint: "https://a.example/t", RefreshToken: "x1"}}.Save(path))
	got, err := LoadCredentials(path)
	require.NoError(t, err)
	assert.Equal(t, "x1", got["x"].RefreshToken)
}

func TestNewSDKSession_StoredCredentialIsReadAgainBeforeRefresh(t *testing.T) {
	// Another run rotated r1 to r2 after this one loaded the file: spending r1
	// would be refused, or revoke the grant at a reuse-detecting provider.
	tok, form := tokenServer(t, http.StatusOK, map[string]string{"access_token": "a", "refresh_token": "r3"})
	ts := bearerServer(t, "Bearer a")
	path := filepath.Join(t.TempDir(), "creds.json")
	require.NoError(t, Credentials{ts.URL: {TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r2"}}.Save(path))
	stale := Credentials{ts.URL: {TokenEndpoint: tok.URL, ClientID: "c", RefreshToken: "r1"}}
	s, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &ts.URL, NonInteractive: true, Credentials: stale, CredentialsFile: path})
	require.NoError(t, err)
	_ = s.Close()
	assert.Equal(t, "r2", form.Load().(url.Values).Get("refresh_token"))
}

func TestStoredLogin_Pin(t *testing.T) {
	u := "https://mcp.example.com/mcp"
	cred := Credential{TokenEndpoint: "https://auth.other.example/token", ClientID: "c1", RefreshToken: "r"}
	cfg := MCPServerConfig{Credentials: Credentials{u: cred}, OAuthTokenEndpoint: "HTTPS://Auth.Other.Example:443/token/"}
	_, ok, why := cfg.storedLogin(u)
	assert.True(t, ok, why) // the pin matches as the client dials it
	assert.False(t, sameEndpoint("https://İ.com/token", "https://i.com/token"), "the dialed IDNA host differs")
	cfg.OAuthTokenEndpoint = "https://auth.other.example/token2"
	_, ok, why = cfg.storedLogin(u)
	assert.False(t, ok)
	assert.Contains(t, why, "the pinned https://auth.other.example/token2", "the message names the pin")
	assert.False(t, sameEndpoint("https://a.example/t", ""), "no pin matches nothing")
	assert.False(t, sameEndpoint("https://a.example/t", "https://a.example/t?x=1"))
	assert.False(t, sameEndpoint("https://a.example:8443/t", "https://a.example:8/t"))
}
