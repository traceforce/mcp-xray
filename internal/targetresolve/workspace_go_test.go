package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewGoProject(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "go.mod")
	writeFile(t, manifest, "module github.com/example/my-server\n\ngo 1.22\n")

	p, err := newGoProject(manifest)
	if err != nil {
		t.Fatalf("newGoProject returned error: %v", err)
	}
	if p.Name != "my-server" {
		t.Errorf("expected name 'my-server' (last module path segment), got %q", p.Name)
	}
	if p.Ecosystem != "go" {
		t.Errorf("expected ecosystem 'go', got %q", p.Ecosystem)
	}
	if p.Dir != root {
		t.Errorf("expected Dir %q, got %q", root, p.Dir)
	}
}

func TestResolveGoLocalDeps_ReplaceDirective(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "go.mod"), `module github.com/example/server

go 1.22

require github.com/example/shared v0.0.0

replace github.com/example/shared => ../shared
`)
	writeFile(t, filepath.Join(sharedDir, "go.mod"), "module github.com/example/shared\n\ngo 1.22\n")

	server, err := newGoProject(filepath.Join(serverDir, "go.mod"))
	if err != nil {
		t.Fatalf("newGoProject(server) error: %v", err)
	}
	shared, err := newGoProject(filepath.Join(sharedDir, "go.mod"))
	if err != nil {
		t.Fatalf("newGoProject(shared) error: %v", err)
	}

	projects := []*Project{server, shared}
	resolveGoLocalDeps(projects)

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
	if len(shared.LocalDeps) != 0 {
		t.Errorf("expected shared to have no local deps, got %v", shared.LocalDeps)
	}
}

func TestResolveGoLocalDeps_RequirePathMatchWithoutReplace(t *testing.T) {
	// Simulates a go.work-based workspace: the server's go.mod requires the
	// shared module by path with no `replace` directive at all -- go.work's
	// `use` entries would resolve this locally in a real build. This package
	// does not need to parse go.work itself for this to work: matching the
	// require path against another module physically present in the repo is
	// sufficient on its own (see the comment on resolveGoLocalDeps).
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "go.mod"), `module github.com/example/server

go 1.22

require github.com/example/shared v0.0.0
`)
	writeFile(t, filepath.Join(sharedDir, "go.mod"), "module github.com/example/shared\n\ngo 1.22\n")

	server, _ := newGoProject(filepath.Join(serverDir, "go.mod"))
	shared, _ := newGoProject(filepath.Join(sharedDir, "go.mod"))
	projects := []*Project{server, shared}
	resolveGoLocalDeps(projects)

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveGoLocalDeps_RegistryOnlyDependencyIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	writeFile(t, filepath.Join(serverDir, "go.mod"), `module github.com/example/server

go 1.22

require github.com/spf13/cobra v1.10.1
`)
	server, _ := newGoProject(filepath.Join(serverDir, "go.mod"))
	resolveGoLocalDeps([]*Project{server})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for a registry-only dependency, got %v", server.LocalDeps)
	}
}
