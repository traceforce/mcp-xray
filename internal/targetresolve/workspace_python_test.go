package targetresolve

import (
	"path/filepath"
	"slices"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestNewPythonProject_PEP621Name(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pyproject.toml")
	writeFile(t, manifest, "[project]\nname = \"my-py-server\"\n")

	p, err := newPythonProject(manifest)
	if err != nil {
		t.Fatalf("newPythonProject returned error: %v", err)
	}
	if p.Name != "my-py-server" {
		t.Errorf("expected name 'my-py-server', got %q", p.Name)
	}
}

func TestNewPythonProject_PoetryNameFallback(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pyproject.toml")
	writeFile(t, manifest, "[tool.poetry]\nname = \"poetry-server\"\n")

	p, err := newPythonProject(manifest)
	if err != nil {
		t.Fatalf("newPythonProject returned error: %v", err)
	}
	if p.Name != "poetry-server" {
		t.Errorf("expected name 'poetry-server', got %q", p.Name)
	}
}

func TestResolvePythonLocalDeps_PoetryPathDependency(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[tool.poetry]
name = "server"

[tool.poetry.dependencies]
python = "^3.10"
shared-lib = { path = "../shared", develop = true }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[tool.poetry]\nname = \"shared-lib\"\n")

	server, err := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("newPythonProject(server) error: %v", err)
	}
	shared, err := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("newPythonProject(shared) error: %v", err)
	}
	resolvePythonLocalDeps(root, []*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
	if len(server.DevLocalDeps) != 0 {
		t.Errorf("a [tool.poetry.dependencies] dependency is needed at run time, got DevLocalDeps %v", server.DevLocalDeps)
	}
}

func TestResolvePythonLocalDeps_UvSourcesPath(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[project]
name = "server"
dependencies = ["shared-lib"]

[tool.uv.sources]
shared-lib = { path = "../shared" }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[project]\nname = \"shared-lib\"\n")

	server, _ := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	shared, _ := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	resolvePythonLocalDeps(root, []*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolvePythonLocalDeps_UvSourcesWorkspaceTrue(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[project]
name = "server"
dependencies = ["shared-lib"]

[tool.uv.sources]
shared-lib = { workspace = true }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[project]\nname = \"shared-lib\"\n")

	server, _ := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	shared, _ := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	resolvePythonLocalDeps(root, []*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q] via workspace=true name match, got %v", shared.Dir, server.LocalDeps)
	}
}

// A uv workspace member listed only in a dependency group is a development
// dependency; one in [project].dependencies is needed at run time.
func TestResolvePythonLocalDeps_DependencyGroupsAreDevelopmentOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `
[project]
name = "sdk"
dependencies = ["helpers"]

[dependency-groups]
dev = ["examples"]

[tool.uv.sources]
helpers = { workspace = true }
examples = { workspace = true }
`)
	writeFile(t, filepath.Join(root, "helpers", "pyproject.toml"), "[project]\nname = \"helpers\"\n")
	writeFile(t, filepath.Join(root, "examples", "pyproject.toml"), "[project]\nname = \"examples\"\n")
	var projects []*Project
	for _, dir := range []string{root, filepath.Join(root, "helpers"), filepath.Join(root, "examples")} {
		p, err := newPythonProject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projects = append(projects, p)
	}

	resolvePythonLocalDeps(root, projects)

	sdk := projects[0]
	if len(sdk.LocalDeps) != 2 {
		t.Fatalf("LocalDeps = %v, want helpers and examples", sdk.LocalDeps)
	}
	if len(sdk.DevLocalDeps) != 1 || sdk.DevLocalDeps[0] != filepath.Join(root, "examples") {
		t.Errorf("DevLocalDeps = %v, want only examples", sdk.DevLocalDeps)
	}
}

// Poetry groups are development only, also for a PEP 621 project with no
// [tool.poetry.dependencies], while a dependency the project needs at run
// time stays a runtime one when a group repeats it.
func TestResolvePythonLocalDeps_PoetryGroupsAreDevelopmentOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `
[project]
name = "app"
dependencies = ["core"]

[tool.poetry.group.dev.dependencies]
core = { path = "core", develop = true }
fixtures = { path = "fixtures" }
`)
	writeFile(t, filepath.Join(root, "core", "pyproject.toml"), "[project]\nname = \"core\"\n")
	writeFile(t, filepath.Join(root, "fixtures", "pyproject.toml"), "[project]\nname = \"fixtures\"\n")
	var projects []*Project
	for _, dir := range []string{root, filepath.Join(root, "core"), filepath.Join(root, "fixtures")} {
		p, err := newPythonProject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projects = append(projects, p)
	}

	resolvePythonLocalDeps(root, projects)

	app := projects[0]
	if len(app.LocalDeps) != 2 {
		t.Fatalf("LocalDeps = %v, want core and fixtures", app.LocalDeps)
	}
	if len(app.DevLocalDeps) != 1 || app.DevLocalDeps[0] != filepath.Join(root, "fixtures") {
		t.Errorf("DevLocalDeps = %v, want only fixtures", app.DevLocalDeps)
	}
}

// A pyproject.toml declaring no project name (tool settings only) is no
// package a workspace source can name, whatever its directory is called.
func TestResolvePythonLocalDeps_UnnamedProjectIsNotADependency(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "pyproject.toml"), `[project]
name = "server"
dependencies = ["tools"]

[tool.uv.sources]
tools = { workspace = true }
`)
	writeFile(t, filepath.Join(root, "tools", "pyproject.toml"), "[tool.ruff]\nline-length = 100\n")

	server, _ := newPythonProject(filepath.Join(root, "server", "pyproject.toml"))
	tools, _ := newPythonProject(filepath.Join(root, "tools", "pyproject.toml"))
	resolvePythonLocalDeps(root, []*Project{server, tools})

	if len(server.LocalDeps) != 0 {
		t.Errorf("server.LocalDeps = %v, want none", server.LocalDeps)
	}
}

// As uv does, a workspace member inherits the root's [tool.uv.sources] for
// the dependencies it declares: the Python SDK's example servers depend on
// "mcp", which the root's `mcp = { workspace = true }` makes the SDK in the
// repository, and an inherited path is relative to the root. A member's own
// source for a name wins, a name it does not declare is not inherited, and
// a project the members globs leave out, or the exclude globs take out,
// inherits nothing.
func TestResolvePythonLocalDeps_InheritsUvWorkspaceRootSources(t *testing.T) {
	root := t.TempDir()
	manifests := map[string]string{
		".": `[project]
name = "mcp"
dependencies = ["mcp-types"]

[tool.uv.workspace]
members = ["src/mcp-types", "examples/servers/*"]
exclude = ["examples/servers/legacy"]

[tool.uv.sources]
mcp = { workspace = true }
mcp-types = { workspace = true }
helpers = { path = "libs/helpers" }
`,
		"src/mcp-types":            "[project]\nname = \"mcp-types\"\n",
		"libs/helpers":             "[project]\nname = \"helpers\"\n",
		"vendor/mcp":               "[project]\nname = \"mcp-fork\"\n",
		"examples/servers/weather": "[project]\nname = \"weather\"\ndependencies = [\"mcp\"]\n\n[dependency-groups]\ndev = [\"helpers\"]\n",
		"examples/servers/pinned":  "[project]\nname = \"pinned\"\ndependencies = [\"mcp\"]\n\n[tool.uv.sources]\nmcp = { path = \"../../../vendor/mcp\" }\n",
		"tools/outside":            "[project]\nname = \"outside\"\ndependencies = [\"mcp\"]\n",
		"examples/servers/legacy":  "[project]\nname = \"legacy\"\ndependencies = [\"mcp\"]\n",
	}
	projects := map[string]*Project{}
	var all []*Project
	for dir, manifest := range manifests {
		writeFile(t, filepath.Join(root, dir, "pyproject.toml"), manifest)
		p, err := newPythonProject(filepath.Join(root, dir, "pyproject.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projects[dir], all = p, append(all, p)
	}

	resolvePythonLocalDeps(root, all)

	for dir, want := range map[string][]string{
		"examples/servers/weather": {root, filepath.Join(root, "libs", "helpers")},
		"examples/servers/pinned":  {filepath.Join(root, "vendor", "mcp")},
		"tools/outside":            nil,
		"examples/servers/legacy":  nil,
	} {
		if got := projects[dir].LocalDeps; !slices.Equal(got, want) {
			t.Errorf("%s LocalDeps = %v, want %v", dir, got, want)
		}
	}
	if weather := projects["examples/servers/weather"]; !slices.Equal(weather.DevLocalDeps, []string{filepath.Join(root, "libs", "helpers")}) {
		t.Errorf("weather DevLocalDeps = %v, want only helpers, a dependency group's", weather.DevLocalDeps)
	}
}

// A project with dynamic dependencies lists them in a Hatch metadata hook;
// python-sdk's SDK depends on its mcp-types sibling only there.
func TestPythonRuntimeDependencies_HatchMetadataHook(t *testing.T) {
	cases := []struct {
		name, toml string
		want       bool
	}{
		{"dynamic dependencies from a hook", "[project]\nname = \"mcp\"\ndynamic = [\"version\", \"dependencies\"]\n\n[tool.hatch.metadata.hooks.uv-dynamic-versioning]\ndependencies = [\"anyio>=4.9\", \"mcp-types=={{ version }}\"]\n", true},
		{"static dependencies ignore the hook", "[project]\nname = \"mcp\"\ndependencies = [\"anyio\"]\n\n[tool.hatch.metadata.hooks.custom]\ndependencies = [\"mcp-types\"]\n", false},
		{"malformed dynamic field", "[project]\nname = \"mcp\"\ndynamic = \"dependencies\"\n\n[tool.hatch.metadata.hooks.custom]\ndependencies = [\"mcp-types\"]\n", false},
	}
	for _, tc := range cases {
		var doc map[string]interface{}
		if err := toml.Unmarshal([]byte(tc.toml), &doc); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := pythonRuntimeDependencies(doc)["mcp-types"]; got != tc.want {
			t.Errorf("%s: mcp-types is a runtime dependency = %v, want %v", tc.name, got, tc.want)
		}
	}
}
