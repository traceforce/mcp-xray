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
	"sync/atomic"
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

// LoadCredentials reads a credentials file; a missing or empty file is an empty set.
func LoadCredentials(path string) (Credentials, error) {
	// Refused like an ssh key when others can read it (Unix only: Windows has no mode bits).
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("credentials file %s is accessible by group or others; run chmod 600 on it", path)
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}
	var creds Credentials
	if len(bytes.TrimSpace(data)) > 0 {
		// Strict: a login entry with a field this version does not know is refused rather
		// than loaded and silently dropped on the next Save (a whole MCP config pasted by
		// mistake is caught by the entry loop below).
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
		for server, c := range creds { // {"mcpServers": {}} decodes too
			if c.TokenEndpoint == "" || c.RefreshToken == "" {
				return nil, fmt.Errorf("failed to parse credentials file: %q is not a stored login", server)
			}
		}
	}
	if creds == nil {
		creds = Credentials{}
	}
	return creds, nil
}

// Save writes the credentials through a temporary file, so the file is never
// half written; on Unix it is created owner-only. A symlink keeps pointing at
// the file it names, and where the rename is refused (a single-file bind mount,
// a directory the run cannot write) the file is rewritten in place instead.
func (c Credentials) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return writeInPlace(path, data, err)
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return writeInPlace(path, data, err)
	}
	return nil
}

// writeInPlace rewrites a file whose directory refuses a temp file or a rename,
// as a single-file bind mount does; any other write error keeps the old file.
func writeInPlace(path string, data []byte, cause error) error {
	if os.WriteFile(path, data, 0600) != nil {
		return cause
	}
	return nil
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
	return sameEndpoint(c.TokenEndpoint, pinned) || site(m.Hostname()) == site(t.Hostname())
}

// sameEndpoint compares two https URLs as the client dials them: the host in its
// IDNA form (so İ.com and i.com stay apart), port 443 implied, and a trailing
// slash ignored.
func sameEndpoint(a, b string) bool {
	u, err1 := url.Parse(a)
	v, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || u.Scheme != v.Scheme {
		return false
	}
	uh, err1 := idna.Lookup.ToASCII(u.Hostname())
	vh, err2 := idna.Lookup.ToASCII(v.Hostname())
	if err1 != nil || err2 != nil { // IDNA rejects ':' and '_': an IPv6 or underscore host is dialed as written
		uh, vh = u.Hostname(), v.Hostname()
	}
	port := func(u *url.URL) string {
		if u.Port() == "443" {
			return ""
		}
		return u.Port()
	}
	return sameHost(uh, vh) && port(u) == port(v) && u.RawQuery == v.RawQuery &&
		strings.TrimSuffix(u.EscapedPath(), "/") == strings.TrimSuffix(v.EscapedPath(), "/")
}

// storedLogin returns the login stored for url when this entry may use it, and
// otherwise why not ("" when none is stored).
func (cfg MCPServerConfig) storedLogin(url string) (Credential, bool, string) {
	cred, ok := cfg.Credentials[url]
	switch {
	case !ok:
		return cred, false, ""
	case !keepable(url, cred, cfg.OAuthTokenEndpoint):
		return cred, false, cfg.notKeepable()
	}
	return cred, true, ""
}

// notKeepable says why a login is not kept or used, naming the pin when there is one.
func (cfg MCPServerConfig) notKeepable() string {
	if cfg.OAuthTokenEndpoint != "" {
		return "no refresh token, or its token endpoint is neither the pinned " + cfg.OAuthTokenEndpoint + " nor https on the server's own site"
	}
	return "no refresh token, or its token endpoint is not https on the server's own site"
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
	// IDNA can fold full-width digits to an IPv4 literal (１９２.０.２.１０ -> 192.0.2.10);
	// the suffix list would then read it as a domain and merge unrelated addresses.
	if ip := net.ParseIP(ascii); ip != nil {
		return ip.String()
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(ascii); err == nil {
		return s
	}
	return ascii
}

// saveCredentials writes url's entry right after it changes, merged into the file
// as it is now, so a rotated refresh token survives a crash later in the run and
// a run overlapping this one keeps its own rotations.
// ponytail: no file lock; two runs saving at the same instant can still race.
func (cfg MCPServerConfig) saveCredentials(url string) {
	if cfg.CredentialsFile == "" {
		return
	}
	disk, err := LoadCredentials(cfg.CredentialsFile)
	if err == nil {
		disk[url] = cfg.Credentials[url]
		err = disk.Save(cfg.CredentialsFile)
	}
	if err != nil { // the file is left as it is
		credentialsSaveFailed.Store(true)
		fmt.Printf("Error writing credentials file: %v\n", err)
	}
}

var credentialsSaveFailed atomic.Bool

// CredentialsSaveFailed reports whether a save during the run failed, so the run
// can fail at its end after the other servers were still tried.
func CredentialsSaveFailed() bool { return credentialsSaveFailed.Load() }

// tokenClient never follows a redirect: it would resend the refresh token in the
// form body to the Location. Its headerTransport adds MCP X-Ray's User-Agent, so
// token-endpoint calls are not sent as Go's default agent, which some providers refuse.
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
	// Refused, so a new login is worth it: an RFC 6749 error code whatever the status
	// (Atlassian sends 403 unauthorized_client, some servers 200), any 400 or 401
	// (invalid_target, invalid_token), or an endpoint gone or moved for good, which a
	// new login rediscovers.
	// Anything else, such as a WAF's HTML 403, a 405 or a 5xx, is an outage.
	// A 408/429/5xx is an outage even when it carries an RFC error code (429
	// invalid_request, 503 invalid_grant); the stored login stays.
	outage := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5
	refused := !outage && oauthErrorCodes[tok.Error]
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusGone, http.StatusMovedPermanently, http.StatusPermanentRedirect:
		refused = true
	}
	// A 2xx that answered with no access token and a non-empty error is the endpoint
	// refusing the stored token in a non-RFC shape (Slack's 200 {"ok":false,"error":...}),
	// so a new browser login is worth it. temporarily_unavailable, server_error and
	// slow_down are the RFC's transient codes: those stay an outage.
	if resp.StatusCode/100 == 2 && tok.AccessToken == "" && tok.Error != "" &&
		tok.Error != "temporarily_unavailable" && tok.Error != "server_error" && tok.Error != "slow_down" {
		refused = true
	}
	switch {
	case refused: // a refusal wins over any access_token sent with it
		return "", &CredentialError{Err: fmt.Errorf("token endpoint refused the stored refresh token: %s", reason)}
	case resp.StatusCode/100 != 2 || tok.AccessToken == "":
		return "", fmt.Errorf("token refresh failed: %s", reason)
	}
	if tok.RefreshToken != "" {
		c.RefreshToken = tok.RefreshToken
	}
	return tok.AccessToken, nil
}
