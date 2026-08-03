package taint

import "testing"

// Several handlers funnelling into ONE shared helper share a sinkIdentity (the sink file,
// line and api are identical, and the source file is the same for an intra-file flow).
// Engine coverage over them is routinely asymmetric -- OpenGrep's generated rules match
// only some source shapes while CodeQL's dataflow matches all of them. The cross-engine
// merge must never absorb one handler's finding into another's: a duplicate is a cosmetic
// flaw, a dropped finding is a miss.
func TestMergePathsAsymmetricCoverageKeepsDistinctHandlers(t *testing.T) {
	mk := func(fn, engine string) PathRecord {
		return PathRecord{
			VulnClass: "command_injection", SourceFile: "s.py", SinkFile: "s.py",
			SinkLine: 40, SinkAPI: "os.system", SourceFunction: fn, SourceParam: "cmd",
			Engine: engine,
		}
	}
	for _, c := range []struct {
		name  string
		in    []PathRecord
		want  int
		tools []string
	}{
		{
			"opengrep missed toolA",
			[]PathRecord{mk("toolB", "opengrep"), mk("toolA", "codeql"), mk("toolB", "codeql")},
			2, []string{"toolA", "toolB"},
		},
		{
			"engines found disjoint handlers",
			[]PathRecord{mk("toolB", "opengrep"), mk("toolA", "codeql")},
			2, []string{"toolA", "toolB"},
		},
		{
			"opengrep found only the last of three",
			[]PathRecord{mk("t3", "opengrep"), mk("t1", "codeql"), mk("t2", "codeql"), mk("t3", "codeql")},
			3, []string{"t1", "t2", "t3"},
		},
	} {
		got := MergePaths(c.in)
		if len(got) != c.want {
			t.Errorf("%s: got %d records, want %d (a distinct handler was dropped)", c.name, len(got), c.want)
		}
		seen := map[string]bool{}
		for _, p := range got {
			seen[p.SourceFunction] = true
		}
		for _, want := range c.tools {
			if !seen[want] {
				t.Errorf("%s: handler %q is missing from the merged output", c.name, want)
			}
		}
	}
}

// A record whose handler an engine could NOT recover ("unknown") must not merge into a
// concrete one. Letting the wildcard match would reopen the deletion hole from the other
// side: [og(toolA), og(unknown), cq(toolB)] would absorb toolB into the unknown record and
// drop it, while tagging that unrelated record opengrep+codeql. A duplicate is the
// accepted cost; a miss is not.
func TestMergePathsUnknownHandlerDoesNotAbsorb(t *testing.T) {
	mk := func(fn, engine string) PathRecord {
		return PathRecord{VulnClass: "command_injection", SourceFile: "s.py", SinkFile: "s.py",
			SinkLine: 40, SinkAPI: "os.system", SourceFunction: fn, SourceParam: "cmd", Engine: engine}
	}
	// The reproduction from the review: toolB must survive.
	got := MergePaths([]PathRecord{mk("toolA", "opengrep"), mk("unknown", "opengrep"), mk("toolB", "codeql")})
	seen := map[string]bool{}
	for _, p := range got {
		seen[p.SourceFunction] = true
	}
	if !seen["toolB"] {
		t.Errorf("toolB was absorbed by the unknown-handler record and lost (got %v)", seen)
	}
	if len(got) != 3 {
		t.Errorf("want 3 distinct records, got %d (%v)", len(got), seen)
	}
}

// The merge must not depend on the order the engines' records arrive in (CodeQL's is raw
// SARIF result order), or two identical scans could report different finding counts.
func TestMergePathsOrderIndependent(t *testing.T) {
	mk := func(fn, engine string) PathRecord {
		return PathRecord{VulnClass: "command_injection", SourceFile: "s.py", SinkFile: "s.py",
			SinkLine: 40, SinkAPI: "os.system", SourceFunction: fn, SourceParam: "cmd", Engine: engine}
	}
	a := MergePaths([]PathRecord{mk("toolB", "opengrep"), mk("unknown", "codeql"), mk("toolB", "codeql")})
	b := MergePaths([]PathRecord{mk("toolB", "opengrep"), mk("toolB", "codeql"), mk("unknown", "codeql")})
	if len(a) != len(b) {
		t.Errorf("record count depends on input order: %d vs %d", len(a), len(b))
	}
}
