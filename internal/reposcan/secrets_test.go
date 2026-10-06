package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// SARIF regions and editors use 1-based lines. A secret on line 1 must not be
// reported as line 0 (which drops the region), and one on line 2 must say 2.
func TestSecretsScanReportsOneBasedLines(t *testing.T) {
	dir := t.TempDir()
	token := "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
	files := map[string]string{
		"first.env":  "GITHUB_TOKEN=" + token + "\n",
		"second.env": "ONE=1\nGITHUB_TOKEN=" + token + "\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultConfig()
	cfg.ExcludedPaths = nil
	findings, err := NewSecretsScanner(dir, cfg).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int32{"first.env": 1, "second.env": 2}
	got := map[string]int32{}
	for _, f := range findings {
		got[filepath.Base(f.File)] = f.Line
	}
	for name, line := range want {
		if got[name] != line {
			t.Errorf("%s: secret reported on line %d, want %d", name, got[name], line)
		}
	}
}
