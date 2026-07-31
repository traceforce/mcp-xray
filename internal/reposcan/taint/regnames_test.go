package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestJSRegNamesMatchPack is the anti-drift gate for V43-6.
//
// The comment had two halves: add registerResource/prompt/registerPrompt to the JS pack,
// AND note that "the reRegBoundary/reInlineHandler regexes in the #44 adapter want the same
// names." Both halves are done -- but nothing enforces that they STAY done, and the failure
// mode when they drift is silent: the pack produces sources for a handler category the
// adapter has no boundary for, so the upward scan walks past the registration and blames
// the enclosing function. The finding still looks well-formed; it just names the wrong tool.
//
// This reads the ACTUAL query file and the ACTUAL compiled regexes, so neither side can
// move without the other.
func TestJSRegNamesMatchPack(t *testing.T) {
	ql, err := filepath.Abs(filepath.Join("..", "..", "..", "codeql", "javascript", "mcp_taint.ql"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(ql)
	if err != nil {
		// This gate's whole job is to keep the pack's source names and the adapter regexes
		// in sync; if the pack it reads has moved or gone, that is a failure to surface,
		// not a reason to skip (a skipped drift-gate is silently fail-open).
		t.Fatalf("pack not present at %s: %v", ql, err)
	}

	// isMcpSource pins the names in a `reg.getMethodName() = [ ... ]` list.
	m := regexp.MustCompile(`getMethodName\(\)\s*=\s*\[([^\]]*)\]`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("could not find the getMethodName() name list in the JS pack; if the pack " +
			"was restructured, update this gate rather than deleting it")
	}
	pack := map[string]bool{}
	for _, raw := range strings.Split(m[1], ",") {
		if n := strings.Trim(strings.TrimSpace(raw), `"`); n != "" {
			pack[n] = true
		}
	}
	// setRequestHandler is a deliberate asymmetry: it IS a boundary (it encloses a handler)
	// but carries no quoted tool name, so it belongs in reRegBoundary only, never in the
	// name-capturing regexes. Exclude it rather than weakening the gate.
	delete(pack, "setRequestHandler")

	// Pull the alternation back out of each compiled regex, so this tests what the adapter
	// actually matches rather than a second copy of the list.
	alt := regexp.MustCompile(`\(\?:([a-zA-Z|]+)\)`)
	for _, re := range []struct {
		name string
		rx   *regexp.Regexp
	}{
		{"reRegName", reRegName},
		{"reInlineHandler", reInlineHandler},
		{"reRegBoundary", reRegBoundary},
	} {
		g := alt.FindStringSubmatch(re.rx.String())
		if g == nil {
			t.Fatalf("%s: could not extract the registration-name alternation from %q",
				re.name, re.rx.String())
		}
		got := map[string]bool{}
		for _, n := range strings.Split(g[1], "|") {
			got[n] = true
		}
		var missing []string
		for n := range pack {
			if !got[n] {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s omits %v, which the pack DOES make sources: the adapter has no "+
				"registration boundary for those handlers, so findings are attributed to "+
				"the enclosing function instead of the tool", re.name, missing)
		}
	}

	// reRegBoundary additionally carries the dispatcher and the Go SDK forms; make sure the
	// asymmetry above did not quietly drop it.
	if !reRegBoundary.MatchString(".setRequestHandler(") {
		t.Error("reRegBoundary lost setRequestHandler")
	}
}

// TestEnclosingHandlerResourceAndPrompt locks the consequence end to end: a sink inside a
// registerResource / prompt / registerPrompt handler is attributed to THAT handler and
// never leaks upward to a tool declared above it. Covers both the inline form and the
// fully-wrapped form, where the name and the callback both sit BELOW the boundary.
func TestEnclosingHandlerResourceAndPrompt(t *testing.T) {
	cases := map[string]struct {
		src  string
		line int
		fn   string
		prm  string
	}{
		"registerResource-inline": {
			src: "server.tool(\"prior_tool\", (a) => a);\n" +
				"server.registerResource(\"docs\", async (uri) => {\n" +
				"  return readFileSync(uri.path);\n" +
				"});\n",
			line: 3, fn: "docs", prm: "uri",
		},
		"registerResource-wrapped": {
			src: "server.tool(\"prior_tool\", (a) => a);\n" +
				"server.registerResource(\n" +
				"  \"blob\",\n" +
				"  { uriTemplate: t },\n" +
				"  async ({ path }) => {\n" +
				"    return readFileSync(path);\n" +
				"  });\n",
			line: 6, fn: "blob", prm: "path",
		},
		"prompt-inline": {
			src: "server.tool(\"prior_tool\", (a) => a);\n" +
				"server.prompt(\"summarise\", async (args) => {\n" +
				"  exec(args.cmd);\n" +
				"});\n",
			line: 3, fn: "summarise", prm: "args",
		},
		"registerPrompt-wrapped": {
			src: "server.tool(\"prior_tool\", (a) => a);\n" +
				"server.registerPrompt(\n" +
				"  \"review\",\n" +
				"  { argsSchema: z },\n" +
				"  async (input) => {\n" +
				"    exec(input.cmd);\n" +
				"  });\n",
			line: 6, fn: "review", prm: "input",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "s.ts")
			if err := os.WriteFile(f, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			fn, prm := enclosingHandler(f, tc.line)
			if fn == "prior_tool" {
				t.Fatal("attribution leaked to the PRIOR tool -- the false-accusation bug")
			}
			if fn != tc.fn {
				t.Errorf("handler = %q, want %q", fn, tc.fn)
			}
			if prm != tc.prm {
				t.Errorf("param = %q, want %q", prm, tc.prm)
			}
		})
	}
}
