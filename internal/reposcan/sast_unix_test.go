//go:build unix

package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"mcpxray/proto"
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

// A taint engine that fails is skipped without failing the SAST scan, as in a
// full-repository scan, but a target scan's execution record says so instead
// of claiming success, and keeps the YARA pass's findings.
func TestScanDetailed_RecordsAFailedTaintEngineAsPartial(t *testing.T) {
	failingEngine := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(failingEngine, []byte("#!/bin/sh\necho boom >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPXRAY_OPENGREP_BIN", failingEngine)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "h.py"), []byte("os.system(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Root = root

	result := ScanDetailed(context.Background(), root, config, ScannerSelection{SAST: true}, "unit-1", "")

	var sast ScannerExecution
	for _, execution := range result.Executions {
		if execution.Scanner == "sast" {
			sast = execution
		}
	}
	if sast.Status != ScannerPartial || !strings.Contains(sast.Error, "opengrep") {
		t.Errorf("sast execution = %+v, want partial with the opengrep error", sast)
	}
	if len(result.Findings) == 0 || sast.FindingCount != len(result.Findings) {
		t.Errorf("findings = %d, FindingCount = %d; want the YARA findings kept and counted", len(result.Findings), sast.FindingCount)
	}
}

// A taint finding names its file relative to the repository whichever scan
// unit finds it, so a nested unit and the whole repository report the same
// message (and fingerprint) for one flow, as a full-repository scan does.
func TestScanDetailed_TaintFindingNamesTheRepositoryRelativeFile(t *testing.T) {
	repo := t.TempDir()
	server := filepath.Join(repo, "nested", "nsrv", "server.py")
	if err := os.MkdirAll(filepath.Dir(server), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server, []byte("@mcp.tool()\ndef run(cmd: str):\n    os.system(cmd)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	realServer, err := filepath.EvalSymlinks(server) // the engine is handed the resolved root
	if err != nil {
		t.Fatal(err)
	}
	// An engine reporting one command injection at server.py:3.
	result := `{"results":[{"check_id":"mcpxray-py-command_injection","path":"` + realServer + `","start":{"line":3},"end":{"line":3},` +
		`"extra":{"metavars":{"$F":{"abstract_content":"run"},"$SRC":{"abstract_content":"cmd","start":{"line":2}}}}}],"errors":[]}`
	engine := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(engine, []byte("#!/bin/sh\ncat <<'EOF'\n"+result+"\nEOF\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPXRAY_OPENGREP_BIN", engine)

	for _, unitRoot := range []string{repo, filepath.Join(repo, "nested")} {
		config := DefaultConfig()
		config.Root, config.ReportRoot = unitRoot, repo
		var taintFindings []*proto.Finding
		for _, executed := range ScanDetailed(context.Background(), unitRoot, config, ScannerSelection{SAST: true}, "unit", "").Findings {
			if executed.Finding.Tool == "opengrep" {
				taintFindings = append(taintFindings, executed.Finding)
			}
		}
		if len(taintFindings) != 1 {
			t.Fatalf("unit %s: %d taint findings, want the engine's one", unitRoot, len(taintFindings))
		}
		finding := taintFindings[0]
		if !strings.Contains(finding.Message, " at nested/nsrv/server.py:3.") || finding.File != server {
			t.Errorf("unit %s: message %q, file %s; want the sink at nested/nsrv/server.py:3 in %s", unitRoot, finding.Message, finding.File, server)
		}
	}
}
