package libmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// childMode makes the test binary act as a stdio server stub instead of running tests.
const childMode = "MCPXRAY_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childMode) {
	case "banner":
		fmt.Println("Starting stub MCP server in stdio mode...")
		server := mcp.NewServer(&mcp.Implementation{Name: "stub", Version: "0"}, nil)
		server.AddTool(&mcp.Tool{Name: "t", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{}, nil
			})
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
		return
	case "stderr":
		fmt.Fprintln(os.Stderr, "token:", os.Getenv("MCPXRAY_TEST_TOKEN"))
		fmt.Fprintln(os.Stderr, "npm error E401 Unauthorized")
		os.Exit(1)
	case "lastword": // logs only the token of MCPXRAY_TEST_TOKEN="Bearer <token>"
		words := strings.Fields(os.Getenv("MCPXRAY_TEST_TOKEN"))
		fmt.Fprintln(os.Stderr, "invalid token", words[len(words)-1])
		os.Exit(1)
	case "args":
		fmt.Fprintln(os.Stderr, "args:", strings.Join(os.Args[1:], " "))
		os.Exit(1)
	case "stdout":
		fmt.Println("Error: GITHUB_TOKEN not set")
		os.Exit(1)
	case "listen":
		fmt.Println("MCP server listening on http://localhost:3000")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	case "rpcerror":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		var req struct{ ID json.RawMessage }
		_ = json.Unmarshal([]byte(line), &req)
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"bad key %s"}}`+"\n", req.ID, os.Getenv("MCPXRAY_TEST_TOKEN"))
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	case "noisy": // answers initialize, then prints a debug line with no newline before the tools/list reply
		in := bufio.NewReader(os.Stdin)
		for {
			line, err := in.ReadString('\n')
			if err != nil {
				return
			}
			var req struct {
				ID     json.RawMessage
				Method string
			}
			_ = json.Unmarshal([]byte(line), &req)
			switch req.Method {
			case "initialize":
				fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"n","version":"0"}}}`+"\n", req.ID)
			case "tools/list":
				fmt.Printf(`debug: listing tools{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`+"\n", req.ID)
			}
		}
	case "unauthorized":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		var req struct{ ID json.RawMessage }
		_ = json.Unmarshal([]byte(line), &req)
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":"Unauthorized"}}`+"\n", req.ID)
		_, _ = io.Copy(io.Discard, os.Stdin)
		time.Sleep(3 * time.Second)
		return
	}
	os.Exit(m.Run())
}

// childConfig runs this test binary as the stub named by mode.
func childConfig(t *testing.T, mode string) MCPServerConfig {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	if strings.ContainsAny(exe, " \t") {
		t.Skip("NewSDKSession splits Command on whitespace")
	}
	return MCPServerConfig{Name: "s", Command: &exe, Env: map[string]string{childMode: mode}}
}

func TestNewSDKSession_StdioSkipsBanner(t *testing.T) {
	s, err := NewSDKSession(context.Background(), childConfig(t, "banner"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	tools, err := ListAllTools(context.Background(), s.Session)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "t", tools[0].Name)
}

func TestNewSDKSession_StdioExitReportsStderr(t *testing.T) {
	// The token is inherited from the parent environment, not configured for the server.
	t.Setenv("MCPXRAY_TEST_TOKEN", "ghp_secret_0123456789")
	_, err := NewSDKSession(context.Background(), childConfig(t, "stderr"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to connect (stderr: token: [redacted]\nnpm error E401 Unauthorized)")
	assert.NotContains(t, err.Error(), "ghp_secret_0123456789")
	// The child's last line ends with Unauthorized, which must not read as a 401.
	assert.Equal(t, OutcomeFailed, OutcomeForError(err))
}

func TestNewSDKSession_StdioExitRedactsArgSecrets(t *testing.T) {
	cfg := childConfig(t, "args")
	cfg.Args = []string{"-y", "@acme/server-pkg", "--api-key", "sk-0123456789",
		"--token=ghp_0123456789", "postgresql://user:password@db.example/x"}
	_, err := NewSDKSession(context.Background(), cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "(stderr: args: -y [redacted] --api-key [redacted] [redacted] [redacted])")
}

func TestNewSDKSession_StdioExitReportsStdout(t *testing.T) {
	_, err := NewSDKSession(context.Background(), childConfig(t, "stdout"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to connect (stdout: Error: GITHUB_TOKEN not set)")
}

func TestNewSDKSession_StdioConnectTimesOut(t *testing.T) {
	cfg := childConfig(t, "listen")
	cfg.ConnectTimeout = 500 * time.Millisecond
	_, err := NewSDKSession(context.Background(), cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "(stdout: MCP server listening on http://localhost:3000)")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotContains(t, err.Error(), "canceled") // the timer's own cancel is not a second cause
}

func TestNewSDKSession_StdioNoiseAfterInitializeFailsFast(t *testing.T) {
	// Noise sharing a line with a later response must fail the call, as at base,
	// not drop the response and leave a caller without a deadline (pentest) waiting.
	s, err := NewSDKSession(context.Background(), childConfig(t, "noisy"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = s.Session.ListTools(ctx, &mcp.ListToolsParams{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestNewSDKSession_StdioErrorBeforeTimeoutKeepsSDKError(t *testing.T) {
	// The child refuses initialize at once but takes 3 seconds to exit, so the timer
	// fires during the SDK's cleanup; the refusal must not be relabelled a timeout.
	cfg := childConfig(t, "unauthorized")
	cfg.ConnectTimeout = 1500 * time.Millisecond // headroom for the child to start on a slow runner
	_, err := NewSDKSession(context.Background(), cfg)
	require.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, strings.HasSuffix(err.Error(), "Unauthorized"), err.Error()) // OutcomeForError's auth_required match

	t.Setenv("MCPXRAY_TEST_TOKEN", "Unauthorized") // an env value masks the suffix itself
	_, err = NewSDKSession(context.Background(), cfg)
	assert.Equal(t, OutcomeAuthRequired, OutcomeForError(err), err.Error())
}

func TestNewSDKSession_StdioRedactsSDKError(t *testing.T) {
	t.Setenv("MCPXRAY_TEST_TOKEN", "ghp_secret_0123456789")
	_, err := NewSDKSession(context.Background(), childConfig(t, "rpcerror"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "bad key [redacted]")
	assert.NotContains(t, err.Error(), "ghp_secret_0123456789")
}

func TestArgSecrets(t *testing.T) {
	args := []string{"-y", "--api-key", "sk-0123456789", "--token=ghp_0123456789", "short",
		"https://ghp_0123456789:x-oauth-basic@github.com/o/r"}
	assert.Equal(t, []string{"sk-0123456789", "--token=ghp_0123456789", "ghp_0123456789",
		"https://ghp_0123456789:x-oauth-basic@github.com/o/r", "ghp_0123456789", "x-oauth-basic"}, argSecrets(args))
}

func TestArgSecrets_ValueForms(t *testing.T) {
	got := argSecrets([]string{"--api-key", "-PLACEHOLDER_abcdefgh", "-transport", "stdio",
		"https://x.example/mcp?client=x&api_key=PLACEHOLDER_query", "Authorization: Bearer PLACEHOLDER_header"})
	assert.NotContains(t, got, "ransport", "a Go-style single-dash flag is not split")
	assert.Contains(t, argSecrets([]string{"--password=PLACEHOLDER&suffixXYZ"}), "PLACEHOLDER&suffixXYZ")
	for _, want := range []string{"-PLACEHOLDER_abcdefgh", "PLACEHOLDER_query", "PLACEHOLDER_header"} {
		assert.Contains(t, got, want)
	}
}

func TestSecretParts_MasksEveryLoggerEscaping(t *testing.T) {
	// Node and slog leave & raw, Python escapes non-ASCII, and a child may trim.
	secrets := secretParts([]string{"PLACEHOLDER\"VALUE&abcdefgh", "pässwort_abcdefgh", "PLACEHOLDER_trimmed \r\n"})
	for _, logged := range []string{`"PLACEHOLDER\"VALUE&abcdefgh"`, `"PLACEHOLDER\"VALUE\u0026abcdefgh"`,
		`"p\u00e4sswort_abcdefgh"`, "token: PLACEHOLDER_trimmed\nnext line"} {
		got := redact(logged, secrets, false)
		assert.NotContains(t, got, "abcdefgh", logged)
		assert.NotContains(t, got, "PLACEHOLDER_trimmed", logged)
	}
	assert.Equal(t, "token: [redacted]\nnext line", redact("token: PLACEHOLDER_trimmed\nnext line", secrets, false))
}

func TestNewSDKSession_RemoteErrorMasksURLAndHeaderValues(t *testing.T) {
	// Nothing listens there, so Go's error quotes the URL, key included.
	u := "http://127.0.0.1:1/mcp?api_key=PLACEHOLDER_query1"
	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &u, NonInteractive: true})
	require.Error(t, err)
	assert.Contains(t, errors.Unwrap(err).Error(), "PLACEHOLDER_query1", "the SDK error does carry the key")
	assert.NotContains(t, err.Error(), "PLACEHOLDER_query1")

	s := &SDKSession{secrets: remoteSecrets(u, map[string]string{"Authorization": "Bearer --PLACEHOLDER_header1"})}
	assert.EqualError(t, s.Redact(errors.New(`calling "tools/list": bad token --PLACEHOLDER_header1`)), `calling "tools/list": bad token [redacted]`)

	// Go quotes the URL with its password as ***, so the whole URL no longer matches
	// and only the path segment covers the key.
	u = "http://deploy:pw_X@127.0.0.1:1/mcp/sk-ak-PLACEHOLDERKEY123"
	_, err = NewSDKSession(context.Background(), MCPServerConfig{Name: "s", URL: &u, NonInteractive: true})
	require.Error(t, err)
	assert.Contains(t, errors.Unwrap(err).Error(), "sk-ak-PLACEHOLDERKEY123", "the SDK error does carry the key")
	assert.NotContains(t, err.Error(), "sk-ak-PLACEHOLDERKEY123")
}

func TestValueParts_KeyForms(t *testing.T) {
	got := valueParts("https://mcp.example.com/api/mcp/s/PLACEHOLDER_pathtoken1/sse")
	assert.Contains(t, got, "PLACEHOLDER_pathtoken1", "a long path segment, as an SSE messages endpoint echoes it")
	assert.NotContains(t, got, "api", "a short path segment is a word")
	assert.Contains(t, valueParts("X-API-Key:sk-live-0123456789"), "sk-live-0123456789", "mcp-remote's --header Name:value")
	assert.Contains(t, valueParts("session=PLACEHOLDER_cookie1; theme=dark"), "PLACEHOLDER_cookie1", "a cookie piece")
	assert.Empty(t, valueParts(`C:\Users\someone\server.js`), "a Windows path is not a header")
}

func TestNewSDKSession_StdioMasksConfiguredEnvInParts(t *testing.T) {
	// mcp-remote's Windows pattern: --header Authorization:${AUTH_HEADER} with
	// AUTH_HEADER="Bearer <token>", and a child that logs the token alone.
	cfg := childConfig(t, "lastword")
	cfg.Env["MCPXRAY_TEST_TOKEN"] = "Bearer PLACEHOLDER_envtoken1"
	_, err := NewSDKSession(context.Background(), cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid token [redacted]")
	assert.NotContains(t, err.Error(), "PLACEHOLDER_envtoken1")
}

func TestNewSDKSession_StartErrorMasksEnvPrefix(t *testing.T) {
	cmd := "NAME=PLACEHOLDER_startvalue node server.js"
	_, err := NewSDKSession(context.Background(), MCPServerConfig{Name: "s", Command: &cmd})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "PLACEHOLDER_startvalue")
}

func TestArgSecrets_DecodesURLCredentials(t *testing.T) {
	// A percent-encoded password is masked both as written and decoded, since a
	// child may log either form.
	got := argSecrets([]string{"postgresql://alice:long%40password@db.example/x"})
	assert.Contains(t, got, "long%40password")
	assert.Contains(t, got, "long@password")
}

func TestArgSecrets_AuthorityEndsBeforeQuery(t *testing.T) {
	// A later '@' in the query must not extend the password past the authority.
	got := argSecrets([]string{"postgresql://alice:longpassword@db?application_name=team@example.com"})
	assert.Contains(t, got, "longpassword")
	assert.NotContains(t, got, "longpassword@db?application_name=team")
}

func readJSONLines(t *testing.T, in string) string {
	t.Helper()
	got, err := io.ReadAll(&jsonLines{r: bufio.NewReader(strings.NewReader(in)), dropped: io.Discard})
	require.NoError(t, err)
	return string(got)
}

func TestJSONLines(t *testing.T) {
	// Only what comes before the first message is filtered; from there on stdout
	// passes through untouched, so a pretty-printed message arrives whole.
	after := "{\n  \"a\": 1\n}\n[INFO] x\n{\"b\":2}"
	assert.Equal(t, after, readJSONLines(t, "Starting server...\n\n[INFO] up\n  "+after))
	assert.Equal(t, "[{\"a\":1}]\n", readJSONLines(t, "\xef\xbb\xbf[INFO] up\n\xef\xbb\xbf[{\"a\":1}]\n"), "a BOM and a batch")
}

func TestJSONLines_DroppedKeepsIndentForRedaction(t *testing.T) {
	// A secret spanning lines with an indented continuation must reach the
	// dropped stream byte-for-byte, so exact-match redaction still masks it.
	secret := "alpha-secret\n\n  beta-secret"
	in := "preamble\n" + secret + "\n{\"a\":1}\n"
	var dropped outputTail
	dropped.secrets = []string{secret}
	kept, err := io.ReadAll(&jsonLines{r: bufio.NewReader(strings.NewReader(in)), dropped: &dropped})
	require.NoError(t, err)
	assert.Equal(t, "{\"a\":1}\n", string(kept))
	assert.NotContains(t, dropped.String(), "beta-secret")
	assert.Contains(t, dropped.String(), "[redacted]")
}

func TestSecretParts_MasksJSONEscapedForm(t *testing.T) {
	// A child that JSON-logs a secret with a quote emits the escaped form; the
	// escaped variant is a candidate, so redact still masks it.
	var tail outputTail
	tail.secrets = secretParts([]string{"s3cret\"credential42"})
	fmt.Fprint(&tail, "log: {\"token\":\"s3cret\\\"credential42\"}")
	assert.NotContains(t, tail.String(), "credential42")
	assert.Contains(t, tail.String(), "[redacted]")
}

func TestJSONLines_KeptFrameStaysOutOfDiagnostic(t *testing.T) {
	// A secret appears JSON-escaped inside a kept protocol frame; that frame must
	// not reach the diagnostic, so the escaped form is never persisted.
	secret := "s3cret\"credential42"
	in := "{\"error\":\"s3cret\\\"credential42\"}\n"
	var dropped outputTail
	dropped.secrets = secretParts([]string{secret})
	_, err := io.ReadAll(&jsonLines{r: bufio.NewReader(strings.NewReader(in)), dropped: &dropped})
	require.NoError(t, err)
	assert.NotContains(t, dropped.String(), "credential42")
}

func TestJSONLines_LongLines(t *testing.T) {
	// Both lines are far longer than bufio's buffer: the dropped one must not be
	// collected, the kept one must arrive whole.
	progress := strings.Repeat("\rdownloading 42%", 20000)
	message := "{\"k\":\"" + strings.Repeat("v", 100000) + "\"}\n"
	assert.Equal(t, message, readJSONLines(t, progress+"\n"+message))
	assert.Equal(t, "", readJSONLines(t, progress))
}

func TestOutputTail(t *testing.T) {
	var tail outputTail
	for i := 1; i <= outputTailLines+2; i++ {
		fmt.Fprintf(&tail, "line %d\n", i)
	}
	lines := strings.Split(tail.String(), "\n")
	assert.Len(t, lines, outputTailLines)
	assert.Equal(t, "line 3", lines[0])
	assert.Equal(t, "line 12", lines[outputTailLines-1])

	var long outputTail
	fmt.Fprint(&long, strings.Repeat("x", 2*outputTailBytes))
	assert.Len(t, long.String(), outputTailBytes)
}

func TestOutputTail_Redacts(t *testing.T) {
	base, auth := "https://host.example", "https://host.example?token=s3cretvalue"
	overlap := outputTail{secrets: []string{base, auth}}
	fmt.Fprintln(&overlap, "GET", auth, "failed")
	assert.Equal(t, "GET [redacted] failed", overlap.String())

	// The byte cap cuts the buffer inside the secret; no suffix of it may survive.
	secret := "ghp_secret_0123456789"
	cut := outputTail{secrets: []string{secret}}
	fmt.Fprint(&cut, strings.Repeat("x", outputTailBytes-8), secret, strings.Repeat("y", outputTailBytes-8))
	assert.True(t, strings.HasPrefix(cut.String(), "[redacted]y"), cut.String()[:20])

	// A multi-line secret is masked before the line limit can cut it.
	key := "-----BEGIN KEY-----\nAAAA\n-----END KEY-----"
	multi := outputTail{secrets: []string{key}}
	fmt.Fprint(&multi, strings.Repeat("log\n", outputTailLines-1), key, "\nexit 1\n")
	assert.Equal(t, strings.Repeat("log\n", outputTailLines-2)+"[redacted]\nexit 1", multi.String())
}
