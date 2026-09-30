//go:build unix

package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Same guard as the SAST walk: a dangling symlink must not abort the secrets scan and a
// FIFO must not hang it, and a real secret next to them is still found.
func TestSecretsScanSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	secret := "GITHUB_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n"
	if err := os.WriteFile(filepath.Join(dir, "h.env"), []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(dir, "nope"), filepath.Join(dir, "dead")) // dangling symlink
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err) // reading a FIFO would block without the guard
	}

	cfg := DefaultConfig()
	cfg.ExcludedPaths = nil
	findings, err := NewSecretsScanner(dir, cfg).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan must not fail on special files: %v", err)
	}
	if len(findings) == 0 {
		t.Error("the secret in h.env must still be found")
	}
}
