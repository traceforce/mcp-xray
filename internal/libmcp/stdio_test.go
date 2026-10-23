package libmcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

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

func TestJSONLines_LongLines(t *testing.T) {
	// Both lines are far longer than bufio's buffer: the dropped one must not be
	// collected, the kept one must arrive whole.
	progress := strings.Repeat("\rdownloading 42%", 20000)
	message := "{\"k\":\"" + strings.Repeat("v", 100000) + "\"}\n"
	assert.Equal(t, message, readJSONLines(t, progress+"\n"+message))
	assert.Equal(t, "", readJSONLines(t, progress))
}

func TestStderrTail(t *testing.T) {
	var tail stderrTail
	for i := 1; i <= stderrTailLines+2; i++ {
		fmt.Fprintf(&tail, "line %d\n", i)
	}
	lines := strings.Split(tail.String(), "\n")
	assert.Len(t, lines, stderrTailLines)
	assert.Equal(t, "line 3", lines[0])
	assert.Equal(t, "line 12", lines[stderrTailLines-1])

	var long stderrTail
	fmt.Fprint(&long, strings.Repeat("x", 2*stderrTailBytes))
	assert.Len(t, long.String(), stderrTailBytes)
}

func TestStderrTail_Redacts(t *testing.T) {
	base, auth := "https://host.example", "https://host.example?token=s3cretvalue"
	overlap := stderrTail{secrets: []string{base, auth}}
	fmt.Fprintln(&overlap, "GET", auth, "failed")
	assert.Equal(t, "GET [redacted] failed", overlap.String())

	// The byte cap cuts the buffer inside the secret; no suffix of it may survive.
	secret := "ghp_secret_0123456789"
	cut := stderrTail{secrets: []string{secret}}
	fmt.Fprint(&cut, strings.Repeat("x", stderrTailBytes-8), secret, strings.Repeat("y", stderrTailBytes-8))
	assert.True(t, strings.HasPrefix(cut.String(), "[redacted]y"), cut.String()[:20])

	// A multi-line secret is masked before the line limit can cut it.
	key := "-----BEGIN KEY-----\nAAAA\n-----END KEY-----"
	multi := stderrTail{secrets: []string{key}}
	fmt.Fprint(&multi, strings.Repeat("log\n", stderrTailLines-1), key, "\nexit 1\n")
	assert.Equal(t, strings.Repeat("log\n", stderrTailLines-2)+"[redacted]\nexit 1", multi.String())
}
