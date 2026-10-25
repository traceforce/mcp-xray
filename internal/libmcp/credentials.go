package libmcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Credential is what a run needs to log in again without a browser: a refresh
// token and the token endpoint and client it was issued for.
type Credential struct {
	TokenEndpoint string `json:"token_endpoint"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
	RefreshToken  string `json:"refresh_token"`
}

// Credentials maps an MCP server URL, as configured, to its stored credential.
type Credentials map[string]Credential

// CredentialError is returned when the token endpoint refuses a stored
// credential; the server needs a new login.
type CredentialError struct{ Err error }

func (e *CredentialError) Error() string { return e.Err.Error() }
func (e *CredentialError) Unwrap() error { return e.Err }

// CodeExchangeError marks a failure after the browser returned an authorization
// code: the server is auth-gated, so a run must not fall back to an anonymous
// connection that would only turn the token-endpoint outage into auth_required.
type CodeExchangeError struct{ Err error }

func (e *CodeExchangeError) Error() string { return e.Err.Error() }
func (e *CodeExchangeError) Unwrap() error { return e.Err }

// LoadCredentials reads a credentials file; a missing or empty file is an empty set.
func LoadCredentials(path string) (Credentials, error) {
	// Refused like an ssh key when others can read it (Unix only: Windows has no mode bits).
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("credentials file %s is readable by others; run chmod 600 on it", path)
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}
	var creds Credentials
	if len(bytes.TrimSpace(data)) > 0 {
		// Strict, so an MCP config passed by mistake is refused rather than rewritten.
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&creds); err != nil {
			return nil, fmt.Errorf("failed to parse credentials file: %w", err)
		}
		// A lone Decode accepts a valid value followed by another document or junk;
		// reject that so a later save cannot silently drop the trailing content.
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("failed to parse credentials file: unexpected content after the first JSON value")
		}
	}
	if creds == nil {
		creds = Credentials{}
	}
	return creds, nil
}

// Save writes the credentials through a temporary file, so the file is never
// half written; on Unix it is created owner-only.
func (c Credentials) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // a crash must not leave an empty file behind the rename
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// keepable reports whether a login may be stored for and reused by an MCP URL:
// both must be https and the token endpoint on the server's own site, or the one
// the config pins, so a server that names another vendor's authorization server
// never gets a standing login there.
// ponytail: a hosting domain missing from the public suffix list counts as one site; pin to narrow it.
func keepable(mcpURL string, c Credential, pinned string) bool {
	m, err1 := url.Parse(mcpURL)
	t, err2 := url.Parse(c.TokenEndpoint)
	if err1 != nil || err2 != nil || m.Scheme != "https" || t.Scheme != "https" {
		return false
	}
	return c.TokenEndpoint == pinned || site(m.Hostname()) == site(t.Hostname())
}

// site is a host's registrable domain (mcp.example.com -> example.com), or the
// host itself when it has none, such as an IP address or localhost.
func site(host string) string {
	// An IP is its own site; the public suffix list would read it as a domain and
	// fold 192.0.2.10 and 198.51.2.10 both to "2.10", merging unrelated hosts.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// Normalize to the ASCII/punycode form the HTTP client actually dials, so a
	// Unicode host cannot fold to a different registrable domain than the connection.
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return strings.ToLower(host) // unresolvable: only matches an identical host
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(ascii); err == nil {
		return s
	}
	return ascii
}

// isHTTPSURL reports whether s parses as an https URL; the scheme is matched
// case-insensitively, as url.Parse and http.NewRequest normalize it.
func isHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// saveCredentials writes the credentials right after a change, so a rotated
// refresh token survives a crash or cancel later in the run.
func (cfg MCPServerConfig) saveCredentials() {
	if cfg.CredentialsFile == "" {
		return
	}
	if err := cfg.Credentials.Save(cfg.CredentialsFile); err != nil {
		fmt.Printf("Error writing credentials file: %v\n", err)
	}
}

// tokenClient never follows a redirect: it would resend the refresh token in the
// form body to the Location. Its headerTransport adds the configured User-Agent
// (it carries no credential headers of its own), so token-endpoint calls are not
// sent as Go's default agent, which some providers refuse.
var tokenClient = &http.Client{
	Timeout:       20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &headerTransport{base: http.DefaultTransport},
}

// oauthErrorCodes are the RFC 6749 section 5.2 token-endpoint error codes; only
// these are ever reported, since any other value in a refused body is
// server-controlled and could echo a token.
var oauthErrorCodes = map[string]bool{
	"invalid_request":        true,
	"invalid_client":         true,
	"invalid_grant":          true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
	"invalid_scope":          true,
}

// tokenReply is a token endpoint's answer; only its RFC 6749 error code is ever
// reported, as the rest of a refused body may echo a token.
type tokenReply struct {
	TokenResponse
	Error string `json:"error"`
}

func readTokenReply(resp *http.Response) (tokenReply, string) {
	var reply tokenReply
	// The status code only: a server's status text is free text that could carry anything.
	status := strconv.Itoa(resp.StatusCode)
	// A malformed body can populate some fields before the decoder errors; never trust a
	// partial decode, and never surface decoder text that might quote a token.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&reply); err != nil {
		return tokenReply{}, status
	}
	if oauthErrorCodes[reply.Error] {
		return reply, status + " " + reply.Error
	}
	return reply, status
}

// refresh trades the refresh token for an access token at the stored endpoint,
// never one rediscovered from the server, and keeps a rotated refresh token.
func (c *Credential) refresh(resource string) (string, error) {
	if u, err := url.Parse(c.TokenEndpoint); err != nil || u.Scheme != "https" {
		return "", errors.New("token refresh failed: token endpoint is not https")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.RefreshToken},
		"client_id":     {c.ClientID},
		"resource":      {resource},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	resp, err := tokenClient.PostForm(c.TokenEndpoint, form)
	if err != nil {
		// A redirect whose Location echoes the refresh token is parsed before
		// CheckRedirect refuses it, so Go's error can carry the token in any encoding.
		// Report nothing the server controlled, not even a redacted copy.
		return "", errors.New("token refresh failed: the request to the token endpoint did not complete")
	}
	defer resp.Body.Close()
	tok, reason := readTokenReply(resp)
	// A 4xx other than 408/429 refuses the grant; some servers send their error with 200.
	// 408 and 429 are transient (timeout, rate limit), not a refused token.
	ok := resp.StatusCode/100 == 2
	switch {
	case (resp.StatusCode/100 == 4 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout) || (ok && tok.AccessToken == "" && tok.Error != ""):
		return "", &CredentialError{Err: fmt.Errorf("token endpoint refused the stored refresh token: %s", reason)}
	case !ok || tok.AccessToken == "":
		return "", fmt.Errorf("token refresh failed: %s", reason)
	}
	if tok.RefreshToken != "" {
		c.RefreshToken = tok.RefreshToken
	}
	return tok.AccessToken, nil
}
