package targetresolve

import (
	"os"
	"path/filepath"
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
