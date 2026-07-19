package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestEngineIntegration runs the real OpenGrep engine over the fixture. It is opt-in:
// it runs only when MCPXRAY_OPENGREP_BIN points at a pinned engine, so `go test ./...`
// stays deterministic regardless of whatever opengrep may be on PATH.
func TestEngineIntegration(t *testing.T) {
	if os.Getenv("MCPXRAY_OPENGREP_BIN") == "" {
		t.Skip("set MCPXRAY_OPENGREP_BIN to a pinned opengrep to run this integration test")
	}
	cfg := DefaultConfig()
	if cfg.OpengrepBin == "" {
		t.Skip("opengrep not installed; set MCPXRAY_OPENGREP_BIN to run")
	}
	paths, err := NewEngine(cfg).Scan(context.Background(), "testdata/py-vuln")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byClass := map[string]int{}
	tools := map[string]bool{}
	for _, p := range paths {
		byClass[p.VulnClass]++
		tools[p.SourceFunction] = true
	}
	wantClass := map[string]int{"command_injection": 2, "path_traversal": 3, "ssrf": 1, "sqli": 1}
	for cls, min := range wantClass {
		if byClass[cls] < min {
			t.Errorf("%s = %d, want >=%d (paths=%d)", cls, byClass[cls], min, len(paths))
		}
	}
	// read_doc exercises the pathlib Path(...).read_text() sink; exec_cmd is cross-function.
	// read_split exercises the two-statement pathlib receiver form (p = Path(x); p.read_text()).
	for _, want := range []string{"run_ping", "exec_cmd", "read_file", "read_doc", "read_split", "fetch", "lookup"} {
		if !tools[want] {
			t.Errorf("expected a finding attributed to handler %q", want)
		}
	}
}

// TestRunOpenGrepFatalOnBrokenRuleset locks the guarantee that a ruleset the engine
// cannot load (exit >=2) surfaces an error instead of being reported as a clean 0 findings.
func TestRunOpenGrepFatalOnBrokenRuleset(t *testing.T) {
	if os.Getenv("MCPXRAY_OPENGREP_BIN") == "" {
		t.Skip("set MCPXRAY_OPENGREP_BIN to run this integration test")
	}
	cfg := DefaultConfig()
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("rules:\n  - id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runOpenGrep(context.Background(), cfg, bad, "testdata/py-vuln"); err == nil {
		t.Error("a broken ruleset must return an error, not report 0 findings")
	}
}
