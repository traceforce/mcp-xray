package taint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithinRootRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "leak.py")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Skip("symlinks unavailable on this platform")
	}
	if withinRoot(link, root) {
		t.Error("an in-root symlink pointing outside the repo must be rejected")
	}
	real := filepath.Join(root, "real.py")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !withinRoot(real, root) {
		t.Error("a real in-root file must be accepted")
	}
}

func TestResultsToPaths(t *testing.T) {
	root, _ := filepath.Abs("testdata/py-vuln")
	sink := filepath.Join(root, "server.py")
	// Mirror the real OpenGrep shape: $F/$SRC/$SINK metavars come straight from the rule.
	out := &ogOutput{Results: []ogResult{{
		CheckID: "mcpxray-py-command_injection",
		Path:    sink,
		Start:   ogPos{Line: 12},
		End:     ogPos{Line: 12},
		Extra: ogExtra{
			Metavars: map[string]ogMetavar{
				"$F":    {AbstractContent: "run_ping"},
				"$SRC":  {AbstractContent: "host", Start: ogPos{Line: 11}},
				"$SINK": {AbstractContent: `"ping -c 1 "+host`},
			},
			DataflowTrace: ogTrace{IntermediateVars: []ogInterVar{{Content: "host"}}},
		},
	}}}

	paths := resultsToPaths(out, root)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	p := paths[0]
	checks := map[string][2]string{
		"class":  {p.VulnClass, "command_injection"},
		"func":   {p.SourceFunction, "run_ping"},
		"param":  {p.SourceParam, "host"},
		"sink":   {p.SinkAPI, "os.system"},
		"file":   {p.SinkFile, "server.py"},
		"engine": {p.Engine, "opengrep"},
	}
	for name, kv := range checks {
		if kv[0] != kv[1] {
			t.Errorf("%s = %q, want %q", name, kv[0], kv[1])
		}
	}
	if p.SinkLine != 12 {
		t.Errorf("sink line = %d, want 12", p.SinkLine)
	}
	if p.SourceLine != 11 {
		t.Errorf("source line = %d, want 11", p.SourceLine)
	}
}

func TestResultsToPathsConfinesEscapingPath(t *testing.T) {
	root, _ := filepath.Abs("testdata/py-vuln")
	out := &ogOutput{Results: []ogResult{{
		CheckID: "mcpxray-py-command_injection",
		Path:    "/etc/passwd",
		Start:   ogPos{Line: 1},
		Extra:   ogExtra{Metavars: map[string]ogMetavar{"$F": {AbstractContent: "x"}}},
	}}}
	if got := resultsToPaths(out, root); len(got) != 0 {
		t.Fatalf("path outside root must be dropped, got %d", len(got))
	}
}

func TestResultsToPathsRootsRelativePath(t *testing.T) {
	root, _ := filepath.Abs("testdata/py-vuln")
	// A relative engine path must resolve against root, not the process CWD.
	out := &ogOutput{Results: []ogResult{{
		CheckID: "mcpxray-py-command_injection",
		Path:    "server.py",
		Start:   ogPos{Line: 1},
		Extra:   ogExtra{Metavars: map[string]ogMetavar{"$F": {AbstractContent: "run_ping"}}},
	}}}
	got := resultsToPaths(out, root)
	if len(got) != 1 {
		t.Fatalf("relative path must be rooted at root and kept, got %d", len(got))
	}
	if got[0].SinkFile != "server.py" {
		t.Errorf("SinkFile = %q, want server.py", got[0].SinkFile)
	}
}

// TestPathlibLabelFromClass pins the half of the pathlib label that canonicalSinkAPI cannot
// decide on its own, because one line can be two different sinks and only the vuln class
// tells them apart.
//
// The contract: whatever CodeQL's python pack emits for the same file:line, OpenGrep must
// emit too, or sinkIdentity splits one vulnerability into two reports. The pack has no
// read_text/write_text sink -- its only pathlib sink is the Path() construction.
func TestPathlibLabelFromClass(t *testing.T) {
	cases := []struct {
		name, class, api, snippet, want string
	}{
		{"inline read is the Path node for CodeQL", "path_traversal", "pathlib.read_text",
			`return Path(name).read_text()`, "pathlib.Path"},
		{"inline write likewise", "path_traversal", "pathlib.write_text",
			`Path(name).write_text(data)`, "pathlib.Path"},
		{"open() enclosing a Path() argument stays open", "path_traversal", "open",
			`with open(Path(base) / name) as f:`, "open"},
		{"two-statement read has no Path( on the line", "path_traversal", "pathlib.read_text",
			`return p.read_text()`, "pathlib.read_text"},
		{"bare construction is already pathlib.Path", "path_traversal", "pathlib.Path",
			`p = Path(name)`, "pathlib.Path"},
		// The same line is a code_injection at eval AND a path_traversal at Path(). Only the
		// path_traversal finding is corrected; the code_injection keeps the enclosing call.
		{"eval wrapping an inline read keeps eval for code_injection", "code_injection", "eval",
			`data = eval(Path(name).read_text())`, "eval"},
		{"...and becomes pathlib.Path for the path_traversal on the same line", "path_traversal", "eval",
			`data = eval(Path(name).read_text())`, "pathlib.Path"},
		{"other classes are never touched", "command_injection", "os.system",
			`os.system("cat " + str(Path(base) / name))`, "os.system"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pathlibLabelFromClass(c.class, c.api, c.snippet); got != c.want {
				t.Errorf("pathlibLabelFromClass(%q, %q, %q) = %q, want %q",
					c.class, c.api, c.snippet, got, c.want)
			}
		})
	}
}

func TestCanonicalSinkAPI(t *testing.T) {
	cases := map[string]string{
		`os.system("a" + b)`:              "os.system",
		`subprocess.run(cmd, shell=True)`: "subprocess.run+shell=True",
		`open(path)`:                      "open",
		// The ENCLOSING call wins: here the sink is open() and Path() only builds its
		// argument, which is exactly what CodeQL reports. A bare `Path(` test ordered above
		// `open(` claimed this line for pathlib and split the finding across engines.
		`with open(Path(base) / name) as f:`:  "open",
		`data = eval(Path(name).read_text())`: "eval",
		// The inline construction+read is a path_traversal at the Path() node for CodeQL, but
		// that depends on the vuln class -- one line can be two sinks -- so it is corrected by
		// pathlibLabelFromClass, not here. See TestPathlibLabelFromClass.
		`Path(name).read_text()`: "pathlib.read_text",
		// The bare two-statement read/write (no Path( on the line) keeps the precise label.
		`p.read_text()`:                 "pathlib.read_text",
		`p.write_text(data)`:            "pathlib.write_text",
		`requests.get(url)`:             "requests.get",
		`cur.execute(q)`:                "cursor.execute",
		`urllib.request.urlopen(u)`:     "urllib.urlopen",
		`session.request("GET", url=u)`: "http.request",
		// sqlalchemy text() sinks must classify for any argument, not just literals,
		// so cross-engine dedup (SinkAPI is part of pathID) stays stable.
		`text(user_input)`:       "sqlalchemy.text",
		`text(f"select {x}")`:    "sqlalchemy.text",
		`sqlalchemy.text(q)`:     "sqlalchemy.text",
		`something_unrelated(x)`: "unknown_sink",
		// Another object's .text() must NOT be mislabeled as the sqlalchemy.text sink.
		`resp.text(x)`: "unknown_sink",
		// Sinks the CodeQL Python pack selects but the opengrep rules do not: without an
		// arm each falls through to "unknown_sink" (or, for the ones containing "open(",
		// to a wrong label), and SinkAPI feeds the finding title and the dedup keys.
		// `p = Path(name)` is the pack's sink node for the split pathlib form its own
		// fixture (testdata/py-vuln read_split) exercises.
		`p = Path(name)`:           "pathlib.Path",
		`tarfile.open(p)`:          "tarfile.open", // must NOT fall through to "open"
		`zipfile.ZipFile(p)`:       "zipfile.ZipFile",
		`cur.executemany(q, rows)`: "cursor.executemany", // must NOT match .execute(
		`os.remove(p)`:             "os.remove",
		`os.unlink(p)`:             "os.remove",
		`os.mkdir(p)`:              "os.mkdir",
		`shutil.copy(a, b)`:        "shutil.copy",
		`shutil.move(a, b)`:        "shutil.move",
		`requests.put(u)`:          "http.put",
		`requests.delete(u)`:       "http.delete",
		`httpx.put(u)`:             "http.put",
	}
	for in, want := range cases {
		if got := canonicalSinkAPI(in); got != want {
			t.Errorf("canonicalSinkAPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// Two same-named handlers in different source files reaching one shared cross-file sink
// must have distinct identities so they are not falsely deduped.
func TestPathIDIncludesSourceFile(t *testing.T) {
	a := PathRecord{VulnClass: "sqli", SourceFile: "a.py", SinkFile: "shared.py", SinkLine: 9,
		SinkAPI: "cursor.execute", SourceFunction: "run", SourceParam: "q"}
	b := a
	b.SourceFile = "b.py"
	if a.pathID() == b.pathID() {
		t.Error("records differing only in SourceFile must have distinct pathID")
	}
}

func TestFirstErrorMessage(t *testing.T) {
	if got := firstErrorMessage(nil); got != "engine exited with an error" {
		t.Errorf("no errors -> generic message, got %q", got)
	}
	if got := firstErrorMessage([]ogError{{Message: "invalid rule schema", Level: "error"}}); got != "invalid rule schema" {
		t.Errorf("error-level message must surface, got %q", got)
	}
	// Prefer the error-level message over a warning when both are present.
	errs := []ogError{{Message: "a warning", Level: "warn"}, {Message: "the real error", Level: "error"}}
	if got := firstErrorMessage(errs); got != "the real error" {
		t.Errorf("must prefer error level, got %q", got)
	}
}

func TestVulnClassFromCheckID(t *testing.T) {
	if got := vulnClassFromCheckID("mcpxray-py-command_injection"); got != "command_injection" {
		t.Errorf("got %q", got)
	}
	if got := vulnClassFromCheckID("some.namespace.mcpxray-py-ssrf"); got != "ssrf" {
		t.Errorf("namespaced got %q", got)
	}
	if got := vulnClassFromCheckID("unrelated-rule"); got != "" {
		t.Errorf("non-matching should be empty, got %q", got)
	}
}
