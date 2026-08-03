//go:build unix

package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSASTScanSkipsNonRegularFiles guards the demo-ender: a FIFO must not make the walk
// hang forever and a dangling symlink must not abort it -- one bad special file cannot
// take down the scan, and a regular file in the same repo is still analyzed.
func TestSASTScanSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "h.py"), []byte("os.system(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(dir, "nope"), filepath.Join(dir, "dead")) // dangling symlink
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err) // reading a FIFO would block without the guard
	}

	cfg := DefaultConfig()
	cfg.ExcludedPaths = nil // don't exclude anything, so the special files are visited
	findings, err := NewSASTScanner(dir, cfg).Scan(context.Background())
	if err != nil {
		t.Fatalf("scan must not fail on special files: %v", err)
	}
	if len(findings) == 0 {
		t.Error("the unsafe command in h.py must still be found")
	}
}
