package taint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunOpenGrepRejectsRelativeBin locks the fix for the arbitrary-code-execution path:
// runOpenGrep sets cmd.Dir to the scanned (untrusted) repo, and Go resolves a relative
// exec path against Dir, so a relative engine path would run the target repo's own binary.
// It must fail closed before exec.
func TestRunOpenGrepRejectsRelativeBin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OpengrepBin = filepath.Join("bin", "opengrep") // relative on purpose
	_, err := runOpenGrep(context.Background(), cfg, "rules.yaml", "/some/abs/target")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("a relative engine path must be rejected, got err=%v", err)
	}
}

// TestFindOpengrepAbsolutizesEnv locks that a relative MCPXRAY_OPENGREP_BIN is returned as
// an absolute path, so it can never be re-resolved against the scan target at exec time.
func TestFindOpengrepAbsolutizesEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "opengrep"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPXRAY_OPENGREP_BIN", filepath.Join("bin", "opengrep")) // relative

	got := findOpengrep()
	if !filepath.IsAbs(got) {
		t.Fatalf("findOpengrep must absolutize a relative env var, got %q", got)
	}
}
