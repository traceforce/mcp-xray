package taint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cqNode(uri string, line int) cqThreadLoc {
	return cqThreadLoc{Location: cqLoc{PhysicalLocation: cqPhysical{
		ArtifactLocation: cqArtifact{URI: uri},
		Region:           cqRegion{StartLine: line},
	}}}
}

func TestCodeQLParseSarif(t *testing.T) {
	root, _ := filepath.Abs("testdata/py-vuln")
	s := &cqSarif{Runs: []cqRun{{Results: []cqResult{{
		Message: cqText{Text: `MCP-TAINT\[command_injection\]: handler input reaches a command_injection sink.`},
		CodeFlows: []cqCodeFlow{{ThreadFlows: []cqThreadFlow{{
			Locations: []cqThreadLoc{cqNode("server.py", 11), cqNode("server.py", 12)},
		}}}},
	}}}}}
	paths := (&CodeQLEngine{}).parseSarif(s, root)
	if len(paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(paths))
	}
	p := paths[0]
	for name, kv := range map[string][2]string{
		"class": {p.VulnClass, "command_injection"},
		"func":  {p.SourceFunction, "run_ping"},
		"param": {p.SourceParam, "host"},
		"sink":  {p.SinkAPI, "os.system"},
		"file":  {p.SinkFile, "server.py"},
		"eng":   {p.Engine, "codeql"},
	} {
		if kv[0] != kv[1] {
			t.Errorf("%s = %q, want %q", name, kv[0], kv[1])
		}
	}
	if p.SinkLine != 12 {
		t.Errorf("sink line = %d, want 12", p.SinkLine)
	}
}

func TestCodeQLParseSarifConfinesEscapingPath(t *testing.T) {
	root, _ := filepath.Abs("testdata/py-vuln")
	s := &cqSarif{Runs: []cqRun{{Results: []cqResult{{
		Message:   cqText{Text: `MCP-TAINT\[ssrf\]`},
		CodeFlows: []cqCodeFlow{{ThreadFlows: []cqThreadFlow{{Locations: []cqThreadLoc{cqNode("../../../etc/passwd", 1)}}}}},
	}}}}}
	if got := (&CodeQLEngine{}).parseSarif(s, root); len(got) != 0 {
		t.Fatalf("path outside root must be dropped, got %d", len(got))
	}
}

func TestNormURI(t *testing.T) {
	for in, want := range map[string]string{
		"server.py":         "server.py",
		"src/my%20tool.py":  "src/my tool.py",
		"file:///repo/x.py": "/repo/x.py",
		"a/b%2Bc.ts":        "a/b+c.ts",
	} {
		if got := normURI(in); got != want {
			t.Errorf("normURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnclosingHandlerAndFirstParam(t *testing.T) {
	file, _ := filepath.Abs("testdata/py-vuln/server.py")
	if fn, p := enclosingHandler(file, 12); fn != "run_ping" || p != "host" {
		t.Errorf("enclosingHandler = (%q,%q), want (run_ping,host)", fn, p)
	}
	for in, want := range map[string]string{
		"host: str":                     "host",
		"url string":                    "url",
		"ctx context.Context, x string": "ctx",
		"":                              "unknown",
	} {
		if got := firstParam(in); got != want {
			t.Errorf("firstParam(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHandlerRegexAcrossLanguages locks handler-name attribution for Python, Go (incl.
// methods) and JS/TS (function decls + named arrows), so McpToolName isn't "unknown".
func TestHandlerRegexAcrossLanguages(t *testing.T) {
	match := func(line string) string {
		if m := reHandler.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		if m := reInlineHandler.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		if m := reArrowHandler.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}
	for line, want := range map[string]string{
		"def run_ping(host):":                        "run_ping",
		"func Fetch(url string)":                     "Fetch",
		"func (s *Server) Handle(x string)":          "Handle",
		"function foo(a, b)":                         "foo",
		"export async function bar(y) {":             "bar",
		"const f = (x) => {":                         "f",
		"const g = async (req, res) => {":            "g",
		`server.tool("fetch_url", async (args) => {`: "fetch_url",
		`mcp.registerTool('do_thing', (a, b) => {`:   "do_thing",
	} {
		if got := match(line); got != want {
			t.Errorf("handler name for %q = %q, want %q", line, got, want)
		}
	}
}

// TestEnclosingHandlerInlineCallback locks the fix for the common JS shape: an inline
// `server.tool("name", (args) => ...)` must attribute to the tool name, not a helper
// declared above it.
func TestEnclosingHandlerInlineCallback(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s.ts")
	src := "const parseUrl = (raw) => new URL(raw);\n" +
		"server.tool(\"fetch_url\", async (args) => {\n" +
		"  const u = parseUrl(args.url);\n" +
		"  fetch(u);\n" +
		"});\n"
	if err := os.WriteFile(f, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if fn, _ := enclosingHandler(f, 2); fn != "fetch_url" {
		t.Errorf("inline callback handler = %q, want fetch_url", fn)
	}
}

// TestEnclosingHandlerBoundaries locks handler attribution at a registration boundary: a
// finding is named for its OWN tool and never leaks to a PRIOR tool declared above,
// whether the boundary is nameable (3-arg registerTool) or not (setRequestHandler,
// multi-line). It also locks the enclosure guard: a self-contained registration-like call
// in a handler body is not a boundary, and a named arrow wins over its own body call.
func TestEnclosingHandlerBoundaries(t *testing.T) {
	cases := map[string]struct {
		src  string
		line int
		fn   string
		prm  string
	}{
		// 3-arg registerTool: nameable boundary -> its own tool, never the prior toolA.
		"registerTool-named-no-prior-leak": {
			src: "server.tool(\"toolA\", (a) => { return a; });\n" +
				"server.registerTool(\"toolB\", { schema: z }, (b) => {\n" +
				"  exec(b.cmd);\n" +
				"});\n",
			line: 3, fn: "toolB", prm: "unknown",
		},
		// setRequestHandler: no tool-name string -> honest unknown, does not reach toolA.
		"setRequestHandler": {
			src: "server.tool(\"toolA\", (a) => a);\n" +
				"server.setRequestHandler(CallToolSchema, async (req) => {\n" +
				"  exec(req.params);\n" +
				"});\n",
			line: 3, fn: "unknown", prm: "unknown",
		},
		// A self-contained `.tool(...)` call in a body is not a boundary: the scan passes
		// it and names the real enclosing function, not the string the call carries.
		"body-call-not-boundary": {
			src: "function handleCall(request) {\n" +
				"  telemetry.tool(\"audit\");\n" +
				"  exec(request.params.arguments);\n" +
				"}\n",
			line: 3, fn: "handleCall", prm: "request",
		},
		// A named arrow whose body itself calls a registration API is named for the arrow.
		"named-arrow-over-body-call": {
			src:  "const handler = (req) => { svc.resource(\"x\"); exec(req.cmd); };\n",
			line: 1, fn: "handler", prm: "req",
		},
		// Multi-line registration: the boundary line carries no name string -> unknown.
		"multiline-registration": {
			src: "server.tool(\"toolA\", (a) => a);\n" +
				"server.tool(\n" +
				"  \"toolB\",\n" +
				"  (b) => {\n" +
				"    exec(b);\n" +
				"  }\n" +
				");\n",
			line: 5, fn: "unknown", prm: "unknown",
		},
		// Multi-line def: name captured on the `def f(` line, param list continues below.
		"multiline-def": {
			src: "def run_ping(\n" +
				"    host,\n" +
				"    opts):\n" +
				"    os.system(host)\n",
			line: 4, fn: "run_ping", prm: "unknown",
		},
	}
	for name, c := range cases {
		f := filepath.Join(t.TempDir(), "s")
		if err := os.WriteFile(f, []byte(c.src), 0o644); err != nil {
			t.Fatal(err)
		}
		if fn, p := enclosingHandler(f, c.line); fn != c.fn || p != c.prm {
			t.Errorf("%s: enclosingHandler = (%q,%q), want (%q,%q)", name, fn, p, c.fn, c.prm)
		}
	}
}

// TestSinkAPIColon locks that a sink api containing a colon (node:https.request) is
// captured whole, not truncated at its internal colon, while the trailing ": " delimiter
// still bounds a plain api.
func TestSinkAPIColon(t *testing.T) {
	for msg, want := range map[string]string{
		"MCP-TAINT[ssrf] sink=node:https.request: handler input reaches a ssrf sink.": "node:https.request",
		"MCP-TAINT[command_injection] sink=os.system: handler input reaches a sink.":  "os.system",
	} {
		m := reSinkAPI.FindStringSubmatch(msg)
		if m == nil || m[1] != want {
			t.Errorf("reSinkAPI(%q) = %v, want %q", msg, m, want)
		}
	}
}

// TestCodeQLIntegration runs real CodeQL over the Python fixture (build-free). Skipped
// when the bundle is absent, so CI without it still passes. PackDir is resolved to the
// repo's codeql/ dir since `go test` runs from the package directory.
func TestCodeQLIntegration(t *testing.T) {
	if os.Getenv("MCPXRAY_CODEQL_BIN") == "" {
		t.Skip("set MCPXRAY_CODEQL_BIN to a pinned codeql to run this integration test")
	}
	packs, _ := filepath.Abs("../../../codeql")
	cfg := CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: 600}
	eng := NewCodeQLEngine(cfg)
	if !eng.Available() {
		t.Skip("codeql bundle not installed; set MCPXRAY_CODEQL_BIN to run")
	}
	paths, err := eng.Scan(context.Background(), "testdata/py-vuln", []string{"python"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byClass := map[string]int{}
	for _, p := range paths {
		byClass[p.VulnClass]++
	}
	for _, cls := range []string{"command_injection", "path_traversal", "ssrf", "sqli"} {
		if byClass[cls] < 1 {
			t.Errorf("%s = %d, want >=1 (paths=%d)", cls, byClass[cls], len(paths))
		}
	}
}

// TestCodeQLIntegrationJS runs the real JS/TS CodeQL query over a JS fixture (build-free),
// proving the query matches (not just compiles) and that its sink= tags parse. Skipped
// when the bundle is absent.
func TestCodeQLIntegrationJS(t *testing.T) {
	if os.Getenv("MCPXRAY_CODEQL_BIN") == "" {
		t.Skip("set MCPXRAY_CODEQL_BIN to a pinned codeql to run this integration test")
	}
	packs, _ := filepath.Abs("../../../codeql")
	eng := NewCodeQLEngine(CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: 600})
	if !eng.Available() {
		t.Skip("codeql bundle not installed; set MCPXRAY_CODEQL_BIN to run")
	}
	paths, err := eng.Scan(context.Background(), "testdata/js-vuln", []string{"typescript"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byClass := map[string]int{}
	tools := map[string]bool{}
	sinks := map[string]bool{}
	for _, p := range paths {
		byClass[p.VulnClass]++
		tools[p.SourceFunction] = true
		sinks[p.SinkAPI] = true
	}
	for _, cls := range []string{"command_injection", "path_traversal", "ssrf", "sqli"} {
		if byClass[cls] < 1 {
			t.Errorf("%s = %d, want >=1 (paths=%d)", cls, byClass[cls], len(paths))
		}
	}
	// The inline `server.tool("run_cmd", (args) => ...)` shape must attribute to the tool name.
	if !tools["run_cmd"] {
		t.Errorf("expected a finding attributed to handler run_cmd (got %v)", tools)
	}
	// The 3-arg `registerTool("https_fetch", {schema}, (req) => ...)` shape is not parseable
	// by the inline regex; the adapter must still attribute it to https_fetch via the
	// registration boundary rather than leaking to the prior inline tool ("lookup"). Its
	// presence here can only happen with the boundary fix -- the old scan produced "lookup".
	if !tools["https_fetch"] {
		t.Errorf("registerTool finding must attribute to https_fetch, not leak to a prior tool (got %v)", tools)
	}
	// The pack normalizes the node: specifier prefix (codeql/javascript/mcp_taint.ql), so a
	// `node:https` import reports as https.request -- colon-free, like the fs and
	// child_process branches. reSinkAPI's colon handling is unit-tested in TestSinkAPIColon.
	if !sinks["https.request"] {
		t.Errorf("expected sink api https.request from the node:https import (got %v)", sinks)
	}
}

// TestCodeQLScanSurfacesFailure locks the guarantee that a query CodeQL cannot analyze
// returns an error, so a broken run is never silently reported as a clean 0 findings.
func TestCodeQLScanSurfacesFailure(t *testing.T) {
	if os.Getenv("MCPXRAY_CODEQL_BIN") == "" {
		t.Skip("set MCPXRAY_CODEQL_BIN to run this integration test")
	}
	packs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(packs, "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packs, "python", "mcp_taint.ql"), []byte("not valid ql {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packs, "python", "qlpack.yml"), []byte("name: x/y\nversion: 0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultCodeQLConfig()
	cfg.PackDir = packs
	if _, err := NewCodeQLEngine(cfg).Scan(context.Background(), "testdata/py-vuln", []string{"python"}); err == nil {
		t.Error("a query CodeQL cannot analyze must return an error, not report 0 findings")
	}
}

// TestCodeQLScanRejectsRelativeBin locks the fix for the code-execution path: a relative
// engine path could resolve against the scanned repo and run an attacker binary, so Scan
// must fail closed before exec.
func TestCodeQLScanRejectsRelativeBin(t *testing.T) {
	cfg := CodeQLConfig{Bin: filepath.Join("bin", "codeql"), PackDir: t.TempDir()} // relative bin
	_, err := NewCodeQLEngine(cfg).Scan(context.Background(), t.TempDir(), []string{"python"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("a relative codeql bin must be rejected, got %v", err)
	}
}

// TestFindCodeQLAbsolutizesEnv locks that a relative MCPXRAY_CODEQL_BIN is returned as an
// absolute path, so it can never be re-resolved against the scan target at exec time.
func TestFindCodeQLAbsolutizesEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, codeqlExe()), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPXRAY_CODEQL_BIN", codeqlExe()) // relative
	if got := findCodeQL(); !filepath.IsAbs(got) {
		t.Fatalf("findCodeQL must absolutize a relative env var, got %q", got)
	}
}
