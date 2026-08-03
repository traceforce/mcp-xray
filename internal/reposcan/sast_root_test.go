package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scan root that does not exist (or cannot be read) must FAIL, not report a clean
// zero-finding result. Skipping per-entry walk errors is right for one bad file inside a
// repo, but applying it to the root turned `repo-scan <typo>` into a valid empty SARIF
// with exit 0 -- the worst possible output for a security scanner.
func TestSASTScanFailsOnMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-repo")
	_, err := NewSASTScanner(missing, DefaultConfig()).Scan(context.Background())
	if err == nil {
		t.Fatal("scanning a nonexistent root must return an error, not a clean result")
	}
	if !strings.Contains(err.Error(), "scan root") {
		t.Errorf("error should name the scan root, got %v", err)
	}
}

// A real repo containing an odd (here: dangling-symlink, i.e. non-regular) entry still
// scans: the entry is skipped and the rest is analyzed, so the new scan-root failure check
// must not regress a valid repo into an error. The genuine walk-error skip (err != nil on a
// non-root entry, e.g. an unreadable dir/FIFO) is exercised in sast_unix_test.go, which is
// build-tagged because it needs POSIX-specific setup.
func TestSASTScanSkipsBadEntryButScansRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "h.py"), []byte("os.system(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "dangling"))
	cfg := DefaultConfig()
	cfg.ExcludedPaths = nil
	findings, err := NewSASTScanner(dir, cfg).Scan(context.Background())
	if err != nil {
		t.Fatalf("a dangling entry must not fail the scan: %v", err)
	}
	if len(findings) == 0 {
		t.Error("the unsafe command in h.py must still be found")
	}
}
