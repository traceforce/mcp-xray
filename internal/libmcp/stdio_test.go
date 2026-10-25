package libmcp

import (
	"bufio"
	"context"
	"encoding/json"
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
	old := connectTimeout
	t.Cleanup(func() { connectTimeout = old })
	connectTimeout = 500 * time.Millisecond
	_, err := NewSDKSession(context.Background(), childConfig(t, "listen"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "(stdout: MCP server listening on http://localhost:3000)")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
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
	got, err := io.ReadAll(&jsonLines{r: bufio.NewReader(strings.NewReader(in))})
	require.NoError(t, err)
	return string(got)
}

func TestJSONLines(t *testing.T) {
	in := "Starting server...\n\n{\"a\":1}\r\n  {\"c\":3}\n[INFO] x\nlog line\n\r{\"d\":4}\n{\"b\":2}"
	assert.Equal(t, "{\"a\":1}\r\n{\"c\":3}\n{\"d\":4}\n{\"b\":2}", readJSONLines(t, in))
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

func TestJSONLines_DroppedRedactsJSONValuedSecret(t *testing.T) {
	// A secret that is itself JSON starts with '{', so its first line is kept and
	// its body dropped; the diagnostic must still hold the whole value to redact it.
	secret := "{\n  \"access_token\": \"ghp_secret_0123456789\"\n}"
	in := secret + "\n{\"a\":1}\n"
	var dropped outputTail
	dropped.secrets = []string{secret}
	_, err := io.ReadAll(&jsonLines{r: bufio.NewReader(strings.NewReader(in)), dropped: &dropped})
	require.NoError(t, err)
	assert.NotContains(t, dropped.String(), "ghp_secret_0123456789")
	assert.Contains(t, dropped.String(), "[redacted]")
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
