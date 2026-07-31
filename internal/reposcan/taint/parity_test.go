package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSinkAPILabelParity is the gate V43-4 required before the Python pack could emit
// sink=<api>.
//
// SinkAPI is part of sinkIdentity (the cross-engine merge key). If CodeQL emits a label
// that differs from OpenGrep's canonicalSinkAPI for the SAME call, the two records do not
// merge and one vulnerability is reported twice -- and unlike unknown_sink, a subtly-wrong
// label looks correct, so nobody notices. Python is the only language both engines cover,
// which is exactly where cross-engine corroboration is supposed to happen.
//
// This runs BOTH engines over one fixture and asserts, per (file,line), that the SinkAPI
// strings are identical. It is skipped unless both engines are installed.
func TestSinkAPILabelParity(t *testing.T) {
	og := NewEngine(DefaultConfig())
	if !og.Available() {
		t.Skip("opengrep not installed; set MCPXRAY_OPENGREP_BIN")
	}
	// Resolve the pack from the repo tree, like the sibling integration gates: `go test`
	// runs from the package dir with MCPXRAY_CODEQL_PACKS unset, so DefaultCodeQLConfig's
	// findPackDir returns "" and this gate SKIPs even under codeql-pack-ci's env -- which is
	// exactly how the label-parity regression it guards shipped unnoticed.
	packs, _ := filepath.Abs("../../../codeql")
	cq := NewCodeQLEngine(CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: 600})
	if !cq.Available() {
		t.Skip("codeql not installed; set MCPXRAY_CODEQL_BIN to run")
	}

	root, err := filepath.Abs("testdata/py-parity")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "server.py")); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}

	ctx := context.Background()
	ogPaths, err := og.Scan(ctx, root)
	if err != nil {
		t.Fatalf("opengrep scan: %v", err)
	}
	cqPaths, err := cq.Scan(ctx, root, []string{"python"})
	if err != nil {
		t.Fatalf("codeql scan: %v", err)
	}
	if len(ogPaths) == 0 || len(cqPaths) == 0 {
		t.Fatalf("both engines must produce findings on the fixture (opengrep=%d codeql=%d)",
			len(ogPaths), len(cqPaths))
	}

	// Key on the sink location: the same call reported by both engines.
	type loc struct {
		file string
		line int
	}
	ogAPI := map[loc]string{}
	for _, p := range ogPaths {
		ogAPI[loc{p.SinkFile, p.SinkLine}] = p.SinkAPI
	}

	var compared, unknowns int
	for _, p := range cqPaths {
		if p.SinkAPI == unknownSink {
			unknowns++
			t.Errorf("codeql reported %s at %s:%d -- the pack must emit sink=<api>, "+
				"never fall back to snippet recovery", unknownSink, p.SinkFile, p.SinkLine)
			continue
		}
		want, ok := ogAPI[loc{p.SinkFile, p.SinkLine}]
		if !ok {
			// Only one engine found this call. Not a parity failure -- the engines have
			// different reach -- but it cannot be compared.
			continue
		}
		compared++
		if want != p.SinkAPI {
			t.Errorf("LABEL MISMATCH at %s:%d\n  opengrep: %q\n  codeql:   %q\n"+
				"  these must be identical or sinkIdentity splits and the finding is "+
				"reported twice instead of merged",
				p.SinkFile, p.SinkLine, want, p.SinkAPI)
		}
	}

	if compared == 0 {
		t.Fatal("no sink locations were reported by BOTH engines; the parity gate " +
			"compared nothing and would pass vacuously")
	}
	t.Logf("compared %d sink labels across both engines, %d codeql unknown_sink", compared, unknowns)
}

// TestMergeCorroboratesOnParityFixture is the end-to-end consequence: with labels aligned,
// a vulnerability both engines see must merge into ONE record carrying both engine names,
// not two records. This is what V43-4 was actually protecting.
func TestMergeCorroboratesOnParityFixture(t *testing.T) {
	og := NewEngine(DefaultConfig())
	packs, _ := filepath.Abs("../../../codeql")
	cq := NewCodeQLEngine(CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: 600})
	if !og.Available() || !cq.Available() {
		t.Skip("both engines required")
	}
	root, _ := filepath.Abs("testdata/py-parity")
	ctx := context.Background()
	ogPaths, err := og.Scan(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	cqPaths, err := cq.Scan(ctx, root, []string{"python"})
	if err != nil {
		t.Fatal(err)
	}

	merged := MergePaths(append(append([]PathRecord{}, ogPaths...), cqPaths...))
	var corroborated int
	for _, p := range merged {
		if hasEngine(p.Engine, "opengrep") && hasEngine(p.Engine, "codeql") {
			corroborated++
		}
	}
	if corroborated == 0 {
		t.Errorf("no finding was corroborated by both engines after merge "+
			"(opengrep=%d codeql=%d merged=%d); labels or identities still disagree",
			len(ogPaths), len(cqPaths), len(merged))
	}
	t.Logf("opengrep=%d codeql=%d merged=%d corroborated=%d",
		len(ogPaths), len(cqPaths), len(merged), corroborated)
}
