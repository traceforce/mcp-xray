package taint

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDetectLangs(t *testing.T) {
	got := DetectLangs("testdata/py-vuln", nil)
	if !reflect.DeepEqual(got, []string{"python"}) {
		t.Errorf("DetectLangs = %v, want [python]", got)
	}
}

// The exclude closure must gate DETECTION, not just result-filtering: a language living
// only in an excluded dir must not be detected (else it triggers the Go consent warning
// and, under --codeql-allow-build, gets compiled). Uses a dir name absent from skipDirs so
// the closure -- not the built-in skip list -- is what excludes it.
func TestDetectLangsHonoursExclude(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "thirdparty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "thirdparty", "lib.go"), []byte("package v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := DetectLangs(dir, nil); !reflect.DeepEqual(got, []string{"python", "go"}) {
		t.Errorf("no exclude: got %v, want [python go]", got)
	}
	excl := func(rel string) bool {
		for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
			if seg == "thirdparty" {
				return true
			}
		}
		return false
	}
	if got := DetectLangs(dir, excl); !reflect.DeepEqual(got, []string{"python"}) {
		t.Errorf("exclude thirdparty: got %v, want [python]", got)
	}
}

// Consent is flag-only and never prompts: repo-scan reaches it on the default path for
// any repo containing Go, so a stdin read would stall a piped or unattended scan.
func TestResolveGoBuildConsent(t *testing.T) {
	if !ResolveGoBuildConsent([]string{"go"}, true) {
		t.Error("explicit --codeql-allow-build must allow the Go build")
	}
	if ResolveGoBuildConsent([]string{"python"}, false) {
		t.Error("no Go in the repo must not consent")
	}
	// Go present, no flag -> fail closed, without ever reading stdin.
	if ResolveGoBuildConsent([]string{"go"}, false) {
		t.Error("Go present without --codeql-allow-build must fail closed")
	}
}

func TestMergePaths(t *testing.T) {
	a := PathRecord{VulnClass: "ssrf", SinkFile: "s.py", SourceFunction: "f",
		SinkAPI: "requests.get", SourceParam: "url", SinkLine: 5, Engine: "opengrep"}
	b := a
	b.Engine = "codeql"
	merged := MergePaths([]PathRecord{a, b})
	if len(merged) != 1 {
		t.Fatalf("want 1 merged path, got %d", len(merged))
	}
	if merged[0].Engine != "opengrep+codeql" {
		t.Errorf("engine = %q, want opengrep+codeql", merged[0].Engine)
	}
}

// The engines attribute the source parameter differently on a multi-param handler
// (OpenGrep: real tainted param; CodeQL: the handler's first param). The same sink must
// still merge to one record, keeping the first (OpenGrep) attribution.
func TestMergePathsCrossEngineDiffersOnSourceParam(t *testing.T) {
	og := PathRecord{VulnClass: "command_injection", SinkFile: "s.py", SinkLine: 12,
		SinkAPI: "os.system", SourceFunction: "run", SourceParam: "host", Engine: "opengrep"}
	cq := og
	cq.SourceParam = "ctx" // CodeQL named the handler's first param
	cq.Engine = "codeql"
	merged := MergePaths([]PathRecord{og, cq})
	if len(merged) != 1 {
		t.Fatalf("cross-engine same sink must merge, got %d", len(merged))
	}
	if merged[0].Engine != "opengrep+codeql" || merged[0].SourceParam != "host" {
		t.Errorf("got engine=%q param=%q, want opengrep+codeql/host",
			merged[0].Engine, merged[0].SourceParam)
	}
}

// A duplicate path (same pathID) arriving after a cross-engine merge must be absorbed,
// not appended as a second record.
func TestMergePathsAbsorbsDuplicateAfterMerge(t *testing.T) {
	og := PathRecord{VulnClass: "ssrf", SinkFile: "s.py", SinkLine: 5, SinkAPI: "requests.get",
		SourceFunction: "f", SourceParam: "url", Engine: "opengrep"}
	cq := og
	cq.SourceParam = "u" // codeql attributes a different param -> merges by sinkIdentity
	cq.Engine = "codeql"
	if got := MergePaths([]PathRecord{og, cq, cq}); len(got) != 1 {
		t.Fatalf("duplicate cross-engine path must be absorbed, got %d", len(got))
	}
}

// Two tainted params reach the same sink and both engines find both. Each opengrep param
// pairs with its codeql twin -> 2 merged records, not 4 (no cross-engine double-report).
func TestMergePathsMultiParamCrossEngine(t *testing.T) {
	base := PathRecord{VulnClass: "command_injection", SinkFile: "s.py", SinkLine: 12,
		SinkAPI: "os.system", SourceFunction: "run"}
	mk := func(param, engine string) PathRecord { p := base; p.SourceParam = param; p.Engine = engine; return p }
	got := MergePaths([]PathRecord{mk("a", "opengrep"), mk("b", "opengrep"), mk("x", "codeql"), mk("y", "codeql")})
	if len(got) != 2 {
		t.Fatalf("2 params x 2 engines must merge to 2 records, got %d", len(got))
	}
	for _, p := range got {
		if p.Engine != "opengrep+codeql" {
			t.Errorf("each record should be merged across engines, got %q", p.Engine)
		}
	}
}

// Two same-named handlers in different source files reaching one shared cross-file sink
// are distinct paths; SourceFile in pathID keeps them from being falsely deduped.
func TestMergePathsDistinctSourceFilesNotDeduped(t *testing.T) {
	a := PathRecord{VulnClass: "sqli", SourceFile: "a.py", SinkFile: "shared.py", SinkLine: 9,
		SinkAPI: "cursor.execute", SourceFunction: "run", SourceParam: "q", Engine: "codeql"}
	b := a
	b.SourceFile = "b.py"
	if got := MergePaths([]PathRecord{a, b}); len(got) != 2 {
		t.Fatalf("distinct source files must not dedup, got %d", len(got))
	}
}

// Two distinct tainted params reaching the same sink from ONE engine stay separate
// (single-engine output is unchanged by the cross-engine merge key).
func TestMergePathsSameEngineKeepsDistinctParams(t *testing.T) {
	a := PathRecord{VulnClass: "command_injection", SinkFile: "s.py", SinkLine: 12,
		SinkAPI: "os.system", SourceFunction: "run", SourceParam: "a", Engine: "opengrep"}
	b := a
	b.SourceParam = "b"
	if got := MergePaths([]PathRecord{a, b}); len(got) != 2 {
		t.Fatalf("same-engine distinct params must stay separate, got %d", len(got))
	}
}

// Two distinct flows that share a sink but originate on different source lines with an
// "unknown" handler (the shape that bypasses the sameFlow gate via the exact-match fast
// path) must stay separate. Without SourceLine in pathID they collapsed to one, silently
// dropping a finding -- e.g. two setRequestHandler flows into one shared helper.
func TestMergePathsUnknownHandlerDistinctSourceLines(t *testing.T) {
	mk := func(srcLine int) PathRecord {
		return PathRecord{VulnClass: "command_injection", SourceFile: "s.py", SourceLine: srcLine,
			SourceFunction: "unknown", SourceParam: "arg", SinkFile: "s.py", SinkLine: 40,
			SinkAPI: "os.system", Engine: "codeql"}
	}
	if got := MergePaths([]PathRecord{mk(10), mk(20)}); len(got) != 2 {
		t.Fatalf("distinct unknown-handler flows collapsed: got %d records, want 2", len(got))
	}
}
