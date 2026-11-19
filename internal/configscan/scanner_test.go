package configscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"mcpxray/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An unresolvable host still fails the scan: keep the connection findings,
// scan secrets in the same file, and return the error so the process exits
// non-zero.
func TestScanUnresolvableHostKeepsFindingsAndSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")
	// Split the token so the source contains two literals.
	token := "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
	body := fmt.Sprintf(`{
  "mcpServers": {
    "remote": {
      "url": "http://mcp.invalid/mcp",
      "headers": {
        "Authorization": "Bearer %s"
      }
    }
  }
}
`, token)
	require.NoError(t, os.WriteFile(configPath, []byte(body), 0o644))

	scanner, err := NewConfigScanner(configPath, "token", "", filepath.Join(dir, "tools.json"), 0)
	require.NoError(t, err)

	findings, err := scanner.Scan(context.Background())
	ids := findingRuleIDs(findings)
	assert.Error(t, err)
	assert.Contains(t, ids, "connection-failed-no-response", "the scan dropped connection findings, ids=%v err=%v", ids, err)
	assert.Contains(t, ids, "github-pat", "the scan skipped secrets in the failed config, ids=%v err=%v", ids, err)
}

func TestScanInvalidJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{"), 0o644))

	scanner, err := NewConfigScanner(configPath, "token", "", filepath.Join(dir, "tools.json"), 0)
	require.NoError(t, err)

	findings, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Empty(t, findings)
}

func TestScanStdioConfigSucceeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "local": {
      "command": "/usr/bin/true"
    }
  }
}
`
	require.NoError(t, os.WriteFile(configPath, []byte(body), 0o644))

	scanner, err := NewConfigScanner(configPath, "token", "", filepath.Join(dir, "tools.json"), 0)
	require.NoError(t, err)

	findings, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Contains(t, findingRuleIDs(findings), "stdio-transport-detected")
}

func findingRuleIDs(findings []*proto.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleId)
	}
	return ids
}
