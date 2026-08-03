package taint

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEnclosingHandlerGoOfficialSDKShapes is the unit-level half of the V43-1 attribution
// fix: no engine needed, so it runs everywhere the integration gate skips.
//
// The official SDK registers handlers several ways and all must be nameable. The literal
// form was the gap: its tool name lives in a `&mcp.Tool{Name: "x"}` struct field rather
// than a bare quoted first argument, so it came back "unknown" once the pack started
// producing sources for literal-registered handlers. enclosingHandler scans text, not
// compiled Go, so these fixtures need not compile.
func TestEnclosingHandlerGoOfficialSDKShapes(t *testing.T) {
	const sig = "ctx context.Context, req *mcp.CallToolRequest, args FetchArgs"
	cases := map[string]struct {
		src     string
		line    int
		fn, prm string
	}{
		"inline func literal, wrapped": {
			src: "package main\n" +
				"func main() {\n" +
				"\tmcp.AddTool(s, &mcp.Tool{Name: \"fetch_url\"},\n" +
				"\t\tfunc(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\t\t\thttp.Get(args.URL)\n" +
				"\t\t\treturn nil, nil, nil\n" +
				"\t\t})\n}\n",
			line: 5, fn: "fetch_url", prm: "args",
		},
		"inline func literal, one line": {
			src: "package main\n" +
				"func main() {\n" +
				"\tmcp.AddTool(s, &mcp.Tool{Name: \"fetch_url\"}, func(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\t\thttp.Get(args.URL)\n" +
				"\t\treturn nil, nil, nil\n" +
				"\t})\n}\n",
			line: 4, fn: "fetch_url", prm: "args",
		},
		"tool struct on its own line": {
			src: "package main\n" +
				"func main() {\n" +
				"\tmcp.AddTool(s,\n" +
				"\t\t&mcp.Tool{Name: \"blob\"},\n" +
				"\t\tfunc(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\t\t\thttp.Get(args.URL)\n" +
				"\t\t\treturn nil, nil, nil\n" +
				"\t\t})\n}\n",
			line: 6, fn: "blob", prm: "args",
		},
		// Named for the variable, which is the honest answer and already worked.
		"closure bound to a variable": {
			src: "package main\n" +
				"func main() {\n" +
				"\tlookup := func(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\t\thttp.Get(args.URL)\n" +
				"\t\treturn nil, nil, nil\n" +
				"\t}\n" +
				"\tmcp.AddTool(s, &mcp.Tool{Name: \"lookup\"}, lookup)\n}\n",
			line: 4, fn: "lookup", prm: "args",
		},
		"named function": {
			src: "package main\n" +
				"func runPing(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\thttp.Get(args.URL)\n" +
				"\treturn nil, nil, nil\n}\n",
			line: 3, fn: "runPing", prm: "args",
		},
		// mark3labs' tool name is a helper-call argument (`newTool("run_cmd")`), not a
		// `Name:` struct field, so reGoToolName deliberately does not read it -- "unknown"
		// stays the honest answer rather than mistaking the helper's argument for the tool.
		"mark3labs newTool helper stays unknown": {
			src: "package main\n" +
				"func main() {\n" +
				"\ts.AddTool(newTool(\"run_cmd\"),\n" +
				"\t\tfunc(" + sig + ") (*mcp.CallToolResult, any, error) {\n" +
				"\t\t\thttp.Get(args.URL)\n" +
				"\t\t\treturn nil, nil, nil\n" +
				"\t\t})\n}\n",
			line: 5, fn: "unknown", prm: "args",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "server.go")
			if err := os.WriteFile(f, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			fn, prm := enclosingHandler(f, tc.line)
			if fn != tc.fn {
				t.Errorf("handler = %q, want %q", fn, tc.fn)
			}
			if prm != tc.prm {
				t.Errorf("param = %q, want %q (req is the pointer request the pack excludes)", prm, tc.prm)
			}
			if fn == "main" {
				t.Error("attribution leaked to the enclosing main()")
			}
		})
	}
}

// TestCodeQLIntegrationGoOfficialSDK is the V43-1 gate.
//
// The review's point: sources were scoped to github.com/mark3labs/mcp-go, but a server
// built on the OFFICIAL github.com/modelcontextprotocol/go-sdk produces zero sources, so
// the Go pack reported nothing for every vuln class -- and because Go only runs under
// --codeql-allow-build, a user who opts in gets a clean-looking zero rather than an error.
// The review asked to validate against a REAL official-SDK server, not the docs.
//
// testdata/go-sdk-vuln is that server: both handlers take their tool input as a TYPED
// STRUCT parameter, with no RequireString/GetString accessor anywhere. Before the
// isOfficialSdkHandler/isOfficialSdkSource predicates, this fixture produced 0 paths while
// containing an RCE and a traversal.
//
// Unlike a third-party target, building OUR OWN fixture is safe, so AllowGoBuild is set
// here deliberately -- the Go extractor has no build-free mode.
func TestCodeQLIntegrationGoOfficialSDK(t *testing.T) {
	if os.Getenv("MCPXRAY_CODEQL_BIN") == "" {
		t.Skip("set MCPXRAY_CODEQL_BIN to a pinned codeql to run this integration test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the Go extractor compiles the fixture; a go toolchain is required")
	}
	// Resolve the pack from the repo tree like the sibling gates (TestCodeQLIntegration /
	// TestCodeQLIntegrationJS), NOT via DefaultCodeQLConfig/findPackDir: `go test` runs from
	// the package dir with MCPXRAY_CODEQL_PACKS unset, so findPackDir returns "" and this
	// gate would skip while the others run -- so the CI -run filter could include it and it
	// would still never execute.
	packs, _ := filepath.Abs("../../../codeql")
	cfg := CodeQLConfig{Bin: findCodeQL(), PackDir: packs, TimeoutSec: codeqlTimeoutFromEnv(), AllowGoBuild: true}
	if cfg.TimeoutSec < 900 {
		cfg.TimeoutSec = 900 // database create for Go includes a compile
	}
	eng := NewCodeQLEngine(cfg)
	if !eng.Available() {
		t.Skip("codeql bundle not installed; set MCPXRAY_CODEQL_BIN to run")
	}
	// Warm the module cache before the scan: `database create` for Go compiles the fixture,
	// and on a cold or offline GOMODCACHE the Go extractor exits 0 having extracted nothing
	// -- a silent zero the len(paths)==0 check below would misread as the source-shape
	// regression this gate targets. Download the modules first so a zero means the pack;
	// skip (not fail) when they genuinely cannot be fetched, so the failure names the real
	// cause. `go mod download` (not `go build`) leaves no compiled artifact in the tree.
	dl := exec.Command("go", "mod", "download")
	dl.Dir = "testdata/go-sdk-vuln"
	if out, err := dl.CombinedOutput(); err != nil {
		t.Skipf("cannot fetch the official-SDK fixture's modules (offline cache?): %v\n%s", err, out)
	}

	paths, err := eng.Scan(context.Background(), "testdata/go-sdk-vuln", []string{"go"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("0 paths on an official-SDK server that contains an RCE and a traversal: " +
			"this is the silent-zero the review described, not a clean scan")
	}

	byClass := map[string]int{}
	handlers := map[string]bool{}
	sinks := map[string]bool{}
	params := map[string]bool{}
	for _, p := range paths {
		byClass[p.VulnClass]++
		handlers[p.SourceFunction] = true
		sinks[p.SinkAPI] = true
		params[p.SourceParam] = true
	}
	// command_injection/path_traversal come from the NAMED handlers; ssrf and sqli come
	// ONLY from the closure handlers (inline func literal + variable-bound closure). Before
	// the FuncLit arm in isOfficialSdkHandler those two produced zero sources, so requiring
	// them here fails if the closure shapes ever stop being treated as sources again.
	for _, cls := range []string{"command_injection", "path_traversal", "ssrf", "sqli"} {
		if byClass[cls] < 1 {
			t.Errorf("%s = %d, want >=1 (paths=%d); a missing closure-only class (ssrf/sqli) "+
				"means the FuncLit source arm regressed", cls, byClass[cls], len(paths))
		}
	}
	// Attribution must name the handler, proving the source is the typed struct parameter
	// of a registered official-SDK handler rather than some incidental match.
	//
	// The closure shapes are the point: the official SDK carries the tool name in a STRUCT
	// FIELD (`&mcp.Tool{Name: "fetch_url"}`), not as a bare quoted first argument, so before
	// reGoToolName these came back "unknown" -- a finding the pack could see but the adapter
	// could not name. "fetch_url" is registered with an INLINE func literal and "lookup" with
	// a closure bound to a variable, so both recovery paths are covered.
	for _, h := range []string{"runPing", "readFile", "fetch_url", "lookup"} {
		if !handlers[h] {
			t.Errorf("expected a finding attributed to handler %s (got %v)", h, handlers)
		}
	}
	if handlers["unknown"] {
		t.Errorf("a finding was attributed to \"unknown\": every handler in this fixture is "+
			"nameable, either by declaration or from the Tool{Name:} field (got %v)", handlers)
	}
	if handlers["main"] {
		t.Errorf("attribution leaked to the enclosing main() (got %v)", handlers)
	}
	for _, s := range []string{"os/exec.Command", "os.ReadFile"} {
		if !sinks[s] {
			t.Errorf("expected sink api %s (got %v)", s, sinks)
		}
	}
	// The tainted parameter is the decoded `args` struct. The request parameter is a POINTER
	// and the Go pack excludes it by type, so reporting `req` contradicted the query that
	// produced the finding; firstParam now skips Go pointer params for the same reason.
	if params["req"] {
		t.Errorf("SourceParam = \"req\", the *mcp.CallToolRequest the pack excludes by type; "+
			"want the decoded args struct (got %v)", params)
	}
	if !params["args"] {
		t.Errorf("expected the decoded tool-input struct to be named as the source param (got %v)", params)
	}
}
