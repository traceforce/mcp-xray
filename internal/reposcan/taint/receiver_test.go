package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCodeQLSqliReceiverPrecision is the V43-5 gate, and it is deliberately two-sided.
//
// The review reported false positives: `.query()`/`.execute()`/`.raw()` matched on ANY
// receiver, so a job queue, a query-string builder, and unrelated custom classes were all
// reported as HIGH SQL injection. Constraining the receiver to a database handle fixes
// that -- but over-tightening deletes real sinks, and for a security scanner a false
// NEGATIVE is the worse failure of the two. A one-sided test would have passed while the
// class-based `this.db.query(...)` shape silently stopped being reported.
func TestCodeQLSqliReceiverPrecision(t *testing.T) {
	if os.Getenv("MCPXRAY_CODEQL_BIN") == "" {
		t.Skip("set MCPXRAY_CODEQL_BIN to a pinned codeql to run this integration test")
	}
	packs, _ := filepath.Abs("../../../codeql")
	eng := NewCodeQLEngine(CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: 600})
	if !eng.Available() {
		t.Skip("codeql bundle not installed; set MCPXRAY_CODEQL_BIN to run")
	}

	paths, err := eng.Scan(context.Background(), "testdata/js-sqli-recv", []string{"typescript"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	flagged := map[string]bool{}
	for _, p := range paths {
		if p.VulnClass == "sqli" {
			flagged[p.SourceFunction] = true
		}
	}

	// Real database sinks. Missing one means the receiver constraint deleted a true finding.
	for _, tool := range []string{"t_db_var", "t_pool", "t_this_db"} {
		if !flagged[tool] {
			t.Errorf("FALSE NEGATIVE: %s is a real database sink but was not reported "+
				"(the receiver constraint is too tight); flagged=%v", tool, flagged)
		}
	}
	// The review's false positives. Any of these means the constraint is not doing its job.
	for _, tool := range []string{"t_queue", "t_urlbuilder", "t_custom"} {
		if flagged[tool] {
			t.Errorf("FALSE POSITIVE: %s is not a database sink but was reported as sqli; "+
				"flagged=%v", tool, flagged)
		}
	}
	if len(flagged) == 0 {
		t.Fatal("no sqli findings at all -- the fixture or the pack is broken, and this " +
			"gate would otherwise pass vacuously on the negative cases alone")
	}
}
