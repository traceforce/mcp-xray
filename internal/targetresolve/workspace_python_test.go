package targetresolve

import (
	"path/filepath"
	"testing"
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
	resolvePythonLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
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
	resolvePythonLocalDeps([]*Project{server, shared})

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
	resolvePythonLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q] via workspace=true name match, got %v", shared.Dir, server.LocalDeps)
	}
}
