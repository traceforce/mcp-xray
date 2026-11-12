package targetresolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes content to path, creating parent directories as needed.
// Shared by every test file in this package.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func TestDiscoverProjects_FindsEachEcosystem(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server-a", "go.mod"), "module example.com/server-a\n\ngo 1.22\n")
	writeFile(t, filepath.Join(root, "server-b", "package.json"), `{"name": "server-b"}`)
	writeFile(t, filepath.Join(root, "server-c", "pyproject.toml"), "[project]\nname = \"server-c\"\n")

	projects, err := discoverProjects(root)
	if err != nil {
		t.Fatalf("discoverProjects returned error: %v", err)
	}
	if len(projects) != 3 {
		t.Fatalf("expected 3 projects, got %d: %+v", len(projects), projects)
	}

	byEcosystem := make(map[string]*Project)
	for _, p := range projects {
		byEcosystem[p.Ecosystem] = p
	}
	if byEcosystem["go"] == nil || byEcosystem["go"].Name != "server-a" {
		t.Errorf("expected go project named server-a, got %+v", byEcosystem["go"])
	}
	if byEcosystem["node"] == nil || byEcosystem["node"].Name != "server-b" {
		t.Errorf("expected node project named server-b, got %+v", byEcosystem["node"])
	}
	if byEcosystem["python"] == nil || byEcosystem["python"].Name != "server-c" {
		t.Errorf("expected python project named server-c, got %+v", byEcosystem["python"])
	}
}

func TestDiscoverProjects_SkipsExcludedDirectories(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app", "package.json"), `{"name": "app"}`)
	// A package.json inside node_modules must never be discovered as its own project.
	writeFile(t, filepath.Join(root, "app", "node_modules", "some-dep", "package.json"), `{"name": "some-dep"}`)
	writeFile(t, filepath.Join(root, "app", "vendor", "pkg", "go.mod"), "module example.com/vendored\n")

	projects, err := discoverProjects(root)
	if err != nil {
		t.Fatalf("discoverProjects returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected exactly 1 project (excluded dirs pruned), got %d: %+v", len(projects), projects)
	}
	if projects[0].Name != "app" {
		t.Errorf("expected the discovered project to be 'app', got %q", projects[0].Name)
	}
}

func TestDiscoverProjects_FindsNestedProjects(t *testing.T) {
	// Pattern 5-ish: a nested project (e.g. tool definitions) inside a larger
	// project's directory tree must still be discovered as its own project.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "monorepo", "package.json"), `{"name": "monorepo-root"}`)
	writeFile(t, filepath.Join(root, "monorepo", "tools", "definitions", "pyproject.toml"), "[project]\nname = \"tool-definitions\"\n")

	projects, err := discoverProjects(root)
	if err != nil {
		t.Fatalf("discoverProjects returned error: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected 2 projects (parent + nested), got %d: %+v", len(projects), projects)
	}
}

func TestReadFileCapped(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "package.json")
	writeFile(t, small, `{"name": "x"}`)
	oversized := filepath.Join(dir, "server.py")
	writeFile(t, oversized, "from fastmcp import FastMCP\n")
	if err := os.Truncate(oversized, maxReadFileSize+1); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(small, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	device := filepath.Join(dir, "device.ts")
	if err := os.Symlink("/dev/zero", device); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"regular file", small, true},
		{"symlink to a regular file", link, true},
		{"directory", dir, false},
		{"file over the size cap", oversized, false},
		{"symlink to a device", device, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, statErr := os.Stat(tc.path); statErr != nil && tc.path == device {
				t.Skip("/dev/zero unavailable")
			}
			data, err := readFileCapped(tc.path)
			if (err == nil) != tc.ok {
				t.Fatalf("readFileCapped(%s) error = %v, want ok=%v", tc.name, err, tc.ok)
			}
			if tc.ok && string(data) != `{"name": "x"}` {
				t.Errorf("readFileCapped(%s) = %q", tc.name, data)
			}
		})
	}
}

// The walk visits regular files only, as the scanners do: a symlink among a
// project's sources, here to a server outside the repository, is never read
// as evidence of what the project is, and neither is a source file larger
// than the scanners read.
func TestResolve_SymlinkedAndOversizedSourcesAreNotEvidence(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "server.ts"), `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; new McpServer();`)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "linked", "package.json"), `{"name": "linked", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
	if err := os.Symlink(filepath.Join(outside, "server.ts"), filepath.Join(root, "linked", "index.ts")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	script := filepath.Join(root, "scripts", "server.py")
	writeFile(t, script, "from fastmcp import FastMCP\nmcp = FastMCP(\"x\")\nif __name__ == \"__main__\":\n    mcp.run()\n")
	if err := os.Truncate(script, maxReadFileSize+1); err != nil {
		t.Fatal(err)
	}

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 0 {
		t.Errorf("targets = %v, want none", targetNames(resolution.Targets))
	}
}

// npm and the other tools reading these manifests skip a leading UTF-8 byte
// order mark, so a package.json, server.json or mcp.json saved with one is
// still the manifest it looks like.
func TestJSONManifestsWithByteOrderMark(t *testing.T) {
	dir := t.TempDir()
	const bom = "\xef\xbb\xbf"
	writeFile(t, filepath.Join(dir, "package.json"), bom+`{"name": "my-mcp"}`)
	writeFile(t, filepath.Join(dir, "server.json"), bom+validServerJSON)
	writeFile(t, filepath.Join(dir, "mcp.json"), bom+`{"mcpServers": {}}`)

	if p, err := newNodeProject(filepath.Join(dir, "package.json")); err != nil || p.PackageName != "my-mcp" {
		t.Errorf("newNodeProject = %+v, %v; want the my-mcp package", p, err)
	}
	if _, ok := readRegistryManifest(dir, filepath.Join(dir, "server.json")); !ok {
		t.Error("readRegistryManifest rejected a manifest with a byte order mark")
	}
	if !hasConsumerConfig(&Project{Dir: dir}) {
		t.Error("hasConsumerConfig missed an mcp.json with a byte order mark")
	}
}

// A TOML manifest is parsed by a recursive parser that takes time quadratic
// in its size: one nested too deep kills the process with a stack overflow,
// one too large stalls resolution. Brackets in strings and comments are not
// nesting.
func TestReadTOMLFile_RefusesHostileManifests(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content string
		ok            bool
	}{
		{"an ordinary manifest", "[project]\nname = \"srv\"\ndependencies = [\"mcp>=1\", 'x[cli]']\n[tool.uv.sources]\nmcp = { workspace = true }\n", true},
		{"brackets inside strings and comments", "a = \"" + strings.Repeat("[", 500) + "\"\nb = '''" + strings.Repeat("{", 500) + "'''\n# " + strings.Repeat("[", 500) + "\n", true},
		{"nested beyond the limit", "a = " + strings.Repeat("[", maxTOMLNesting+1) + strings.Repeat("]", maxTOMLNesting+1) + "\n", false},
		{"larger than the limit", "a = \"" + strings.Repeat("x", maxTOMLFileSize) + "\"\n", false},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, "pyproject.toml")
		writeFile(t, path, tc.content)
		var doc map[string]interface{}
		if err := readTOMLFile(path, &doc); (err == nil) != tc.ok {
			t.Errorf("%s: readTOMLFile error = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// Two million nested arrays overflow the parser's stack, which no recover
// catches: resolution must refuse the manifest rather than crash.
func TestResolve_DeeplyNestedManifestDoesNotCrash(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), "[project]\nname = \"x\"\ndependencies = "+strings.Repeat("[", 2_000_000)+strings.Repeat("]", 2_000_000)+"\n")
	writeFile(t, filepath.Join(root, "srv", "Cargo.toml"), "[package]\nname = \"srv\"\n[dependencies]\nrmcp = "+strings.Repeat("[", 2_000_000)+"\n")
	if _, err := Resolve(root); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}
