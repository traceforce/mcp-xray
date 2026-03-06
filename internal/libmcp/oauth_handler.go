package libmcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ErrDCRForbidden is returned when the server rejects Dynamic Client Registration with 403.
// Servers like Figma use pre-registered clients and do not support DCR.
var ErrDCRForbidden = errors.New("DCR not supported: 403 Forbidden")

const (
	ApplicationName    = "Traceforce-mcpxray"
	ApplicationVersion = "1.0.2"
	ProtocolVersion    = "2025-06-18"

	defaultRedirectHost = "127.0.0.1"
	defaultRedirectPort = 8765
	RedirectPath        = "/callback"
)

type OAuthConfig struct {
	MCPUrl       string
	httpClient   *http.Client
	ClientID     string // pre-registered client when server does not support DCR (e.g. Figma)
	ClientSecret string
	RedirectURI  string // from config; when set, used as redirect_uri (e.g. cursor://...); when empty, default http://127.0.0.1:8765/callback
}

func NewOAuthConfig(mcpUrl string, clientID, clientSecret string, redirectURI string) *OAuthConfig {
	return &OAuthConfig{
		MCPUrl:       mcpUrl,
		httpClient:   &http.Client{Timeout: 60 * time.Second},
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}
}

func (o *OAuthConfig) redirectURI() string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fmt.Sprintf("http://%s:%d%s", defaultRedirectHost, defaultRedirectPort, RedirectPath)
}

// useLocalRedirectServer returns true if we can receive the OAuth callback on a local HTTP server.
// When redirect_uri is a custom scheme (e.g. cursor://), the callback goes to the OS/IDE, not to us.
func (o *OAuthConfig) useLocalRedirectServer() bool {
	uri := o.redirectURI()
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}

type PRM struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ClientID               string   `json:"client_id,omitempty"`
	ClientSecret           string   `json:"client_secret,omitempty"`
}

type ASMetadata struct {
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

type DCRResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (o *OAuthConfig) OauthDiscovery() (string, error) {
	fmt.Println("1) Discovering Protected Resource Metadata (PRM)…")
	prm, err := o.DiscoverPRM()
	if err != nil {
		return "", err
	}

	fmt.Println("2) Discovering Authorization Server Metadata…")
	asmd, err := o.DiscoverASMetadata(prm)
	if err != nil {
		return "", err
	}

	scopes := asmd.ScopesSupported
	if len(scopes) == 0 {
		// Fallback to PRM scopes if ASMD scopes are not supported.
		scopes = prm.ScopesSupported
	}
	if len(scopes) == 0 {
		// Fallback to minimal scopes if both PRM and ASMD scopes are not supported.
		scopes = []string{"openid", "email", "profile"}
	}
	scopeStr := strings.Join(scopes, " ")

	var clientID, clientSecret string
	fmt.Println("3) Dynamic Client Registration (public client)…")
	dcr, err := o.DynamicClientRegister(asmd)
	if err != nil {
		if !errors.Is(err, ErrDCRForbidden) {
			return "", err
		}
		// DCR returned 403 (e.g. Figma); use pre-registered client from config or PRM
		if o.ClientID != "" {
			fmt.Println("   Using pre-registered client_id from config")
			clientID, clientSecret = o.ClientID, o.ClientSecret
		} else if prm.ClientID != "" {
			fmt.Println("   Using client_id from Protected Resource Metadata")
			clientID, clientSecret = prm.ClientID, prm.ClientSecret
		} else {
			return "", err
		}
	} else {
		clientID, clientSecret = dcr.ClientID, dcr.ClientSecret
		if clientID == "" {
			log.Fatal("DCR failed: empty client_id")
		}
		fmt.Println("   client_id =", clientID)
	}

	verifier, challenge := makePKCE()
	state := randB64URL(16)
	authURL := o.buildAuthURL(asmd.AuthorizationEndpoint, clientID, scopeStr, challenge, state)

	if !o.useLocalRedirectServer() {
		fmt.Println("4) Redirect URI is a custom scheme (e.g. cursor://); callback will go to Cursor.")
		fmt.Println("5) Opening browser for login/consent…")
		fmt.Println("   If it doesn't open, paste this URL into your browser:")
		fmt.Println(authURL)
		openBrowser(authURL)
		return "", fmt.Errorf("redirect_uri is set to %s; complete authorization in Cursor, then Cursor will store the token", o.redirectURI())
	}

	fmt.Println("4) Starting local redirect server…")
	codeCh := make(chan string, 1)
	errCh := make(chan string, 1)
	shutdownServer := startRedirectServer(codeCh, errCh, defaultRedirectHost, defaultRedirectPort)
	defer shutdownServer() // Ensure server is shut down when function returns

	fmt.Println("5) Opening browser for login/consent…")
	fmt.Println("   If it doesn't open, paste this URL into your browser:")
	fmt.Println(authURL)
	openBrowser(authURL)

	// Wait for callback (no background promises; we block right here)
	var code string
	select {
	case code = <-codeCh:
		// Server will be shut down by defer
	case err := <-errCh:
		shutdownServer() // Shutdown before log.Fatalf (which exits)
		log.Fatalf("OAuth error: %s", err)
	case <-time.After(3 * time.Minute):
		shutdownServer() // Shutdown before log.Fatal (which exits)
		log.Fatal("Timed out waiting for OAuth callback")
	}

	fmt.Println("6) Exchanging code for tokens…")
	tok := o.exchangeCode(asmd.TokenEndpoint, clientID, clientSecret, code, verifier)
	if tok.AccessToken == "" {
		log.Fatal("Token exchange failed: no access_token")
	}
	fmt.Printf(" Access token acquired %+v\n\n", tok)

	return tok.AccessToken, nil
}

// ---------- OAuth discovery ----------

func (o *OAuthConfig) DiscoverPRM() (*PRM, error) {
	// Send initialize without auth to trigger 401
	initPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    ApplicationName,
				"version": ApplicationVersion,
			},
		},
	}

	reqBody, _ := json.Marshal(initPayload)
	req, _ := http.NewRequest("POST", o.MCPUrl, strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", ProtocolVersion)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	params := o.parseWWWAuthenticate(wwwAuth)
	rmURL := params["resource_metadata"]
	if rmURL == "" {
		// fallback per MCP spec: /.well-known/oauth-protected-resource
		rmURL = origin(o.MCPUrl) + "/.well-known/oauth-protected-resource"
	}

	rmResp, err := o.httpClient.Get(rmURL)
	if err != nil {
		return nil, err
	}
	defer rmResp.Body.Close()
	if rmResp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(rmResp.Body)
		return nil, fmt.Errorf("PRM fetch failed: %s %s", rmResp.Status, string(b))
	}

	var prm PRM
	if err := json.NewDecoder(rmResp.Body).Decode(&prm); err != nil {
		return nil, err
	}
	return &prm, nil
}

func (o *OAuthConfig) DiscoverASMetadata(prm *PRM) (*ASMetadata, error) {
	authBase := origin(o.MCPUrl)
	if len(prm.AuthorizationServers) > 0 {
		authBase = strings.TrimRight(prm.AuthorizationServers[0], "/")
	}

	mdURL := authBase + "/.well-known/oauth-authorization-server"
	resp, err := o.httpClient.Get(mdURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// fallback endpoints (MCP authorization spec)
		return &ASMetadata{
			AuthorizationEndpoint: authBase + "/authorize",
			TokenEndpoint:         authBase + "/token",
			RegistrationEndpoint:  authBase + "/register",
			ScopesSupported:       prm.ScopesSupported,
		}, nil
	}

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AS metadata fetch failed: %s %s", resp.Status, string(b))
	}

	var asmd ASMetadata
	if err := json.NewDecoder(resp.Body).Decode(&asmd); err != nil {
		return nil, err
	}
	return &asmd, nil
}

func (o *OAuthConfig) DynamicClientRegister(asmd *ASMetadata) (*DCRResponse, error) {
	regEP := asmd.RegistrationEndpoint
	if regEP == "" {
		regEP = origin(o.MCPUrl) + "/register"
	}

	payload := map[string]any{
		"client_name":                ApplicationName,
		"redirect_uris":              []string{o.redirectURI()},
		"response_types":             []string{"code"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_method": "none", // public client
	}

	b, _ := json.Marshal(payload)
	resp, err := o.httpClient.Post(regEP, "application/json", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			// 403 = server rejects DCR; 404 = registration endpoint does not exist (e.g. Slack)
			return nil, ErrDCRForbidden
		}
		return nil, fmt.Errorf("DCR failed: %s %s", resp.Status, string(body))
	}

	var dcr DCRResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcr); err != nil {
		return nil, err
	}
	fmt.Printf("DCR response: %+v\n", dcr)
	return &dcr, nil
}

// ---------- OAuth browser + PKCE ----------

func makePKCE() (verifier, challenge string) {
	verifier = randB64URL(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = b64url(sum[:])
	return
}

func (o *OAuthConfig) buildAuthURL(authEP, clientID, scope, codeChallenge, state string) string {
	u, _ := url.Parse(authEP)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", o.redirectURI())
	q.Set("scope", scope)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	// MCP recommends RFC8707 resource indicator
	q.Set("resource", o.MCPUrl)

	u.RawQuery = q.Encode()
	return u.String()
}

func (o *OAuthConfig) exchangeCode(tokenEP, clientID, clientSecret, code, codeVerifier string) TokenResponse {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", o.redirectURI())
	data.Set("code_verifier", codeVerifier)
	data.Set("resource", o.MCPUrl)

	req, _ := http.NewRequest("POST", tokenEP, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Token exchange failed: %s %s", resp.Status, string(body))
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		log.Fatalf("Token decode failed: %v", err)
	}
	return tr
}

func startRedirectServer(codeCh chan<- string, errCh chan<- string, host string, port int) func() {
	mux := http.NewServeMux()
	mux.HandleFunc(RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			errCh <- e
			http.Error(w, "OAuth failed, you can close this tab.", 400)
			return
		}
		code := q.Get("code")
		if code == "" {
			errCh <- "missing_code"
			http.Error(w, "Missing code", 400)
			return
		}
		fmt.Fprintf(w, "<html><body><h3>%s MCP OAuth complete.</h3><p>You may close this tab.</p></body></html>", ApplicationName)
		codeCh <- code
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		errCh <- fmt.Sprintf("redirect_listen_failed: %v", err)
		return func() {} // Return no-op function if listen fails
	}
	srv := &http.Server{Handler: mux}

	// Start server in goroutine
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Only send error if server wasn't explicitly closed
			select {
			case errCh <- fmt.Sprintf("redirect_server_error: %v", err):
			default:
			}
		}
	}()

	// Return shutdown function
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// ---------- utilities ----------

func (o *OAuthConfig) parseWWWAuthenticate(h string) map[string]string {
	res := map[string]string{}
	if h == "" {
		return res
	}
	// strip "Bearer"
	h = strings.TrimSpace(h)
	if strings.HasPrefix(strings.ToLower(h), "bearer") {
		h = strings.TrimSpace(h[len("bearer"):])
	}
	re := regexp.MustCompile(`(\w+)=(".*?"|[^,]+)`)
	matches := re.FindAllStringSubmatch(h, -1)
	for _, m := range matches {
		k := m[1]
		v := strings.Trim(m[2], `"`)
		res[k] = v
	}
	return res
}

func origin(raw string) string {
	u, _ := url.Parse(raw)
	return u.Scheme + "://" + u.Host
}

func randB64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64url(b)
}

func b64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func openBrowser(u string) {
	// best-effort; still prints URL for manual copy/paste
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default: // linux, etc.
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
	// don't wait; manual open already supported by printed URL
	_ = cmd.Process.Release()
	_ = context.Background()
}
