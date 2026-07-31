package taint

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
	// regression this gate targets. Build first so a zero means the pack; skip (not fail)
	// when the modules genuinely cannot be fetched, so the failure names the real cause.
	build := exec.Command("go", "build", "./...")
	build.Dir = "testdata/go-sdk-vuln"
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot compile the official-SDK fixture (offline module cache?): %v\n%s", err, out)
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
	for _, p := range paths {
		byClass[p.VulnClass]++
		handlers[p.SourceFunction] = true
		sinks[p.SinkAPI] = true
	}
	for _, cls := range []string{"command_injection", "path_traversal"} {
		if byClass[cls] < 1 {
			t.Errorf("%s = %d, want >=1 (paths=%d)", cls, byClass[cls], len(paths))
		}
	}
	// Attribution must name the handler, proving the source is the typed struct parameter
	// of a registered official-SDK handler rather than some incidental match.
	for _, h := range []string{"runPing", "readFile"} {
		if !handlers[h] {
			t.Errorf("expected a finding attributed to handler %s (got %v)", h, handlers)
		}
	}
	for _, s := range []string{"os/exec.Command", "os.ReadFile"} {
		if !sinks[s] {
			t.Errorf("expected sink api %s (got %v)", s, sinks)
		}
	}
	// NOTE: SourceParam is "req", not "args". The SARIF region gives the line but not the
	// column, so enclosingHandler names the handler's FIRST parameter. That is a known,
	// documented adapter limitation (see enclosingHandler) and is why MergePaths keys on
	// the sink identity rather than the param name -- so it is deliberately not asserted.
}
