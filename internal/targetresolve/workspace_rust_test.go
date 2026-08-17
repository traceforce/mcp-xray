package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewRustProject(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	writeFile(t, manifest, `[package]
name = "browseros-mcp"
version = "0.1.0"
edition = "2021"
`)

	p, err := newRustProject(manifest)
	if err != nil {
		t.Fatalf("newRustProject returned error: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil project for a Cargo.toml with a [package] table")
	}
	if p.Name != "browseros-mcp" {
		t.Errorf("expected name 'browseros-mcp', got %q", p.Name)
	}
	if p.Ecosystem != "rust" {
		t.Errorf("expected ecosystem 'rust', got %q", p.Ecosystem)
	}
}

func TestNewRustProject_VirtualWorkspaceManifestReturnsNil(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	writeFile(t, manifest, `[workspace]
members = ["crates/*"]
`)

	p, err := newRustProject(manifest)
	if err != nil {
		t.Fatalf("newRustProject returned error: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil for a virtual workspace-root Cargo.toml (no [package]), got %+v", p)
	}
}

func TestCargoHasDependency(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	writeFile(t, manifest, `[package]
name = "browseros-mcp"

[dependencies]
rmcp.workspace = true
tokio.workspace = true
`)

	doc, err := readCargoToml(manifest)
	if err != nil {
		t.Fatalf("readCargoToml returned error: %v", err)
	}
	if !cargoHasDependency(doc, "rmcp") {
		t.Error("expected cargoHasDependency to find rmcp even declared via workspace = true (no bare version)")
	}
	if cargoHasDependency(doc, "unrelated-crate") {
		t.Error("expected cargoHasDependency to not match an absent crate")
	}
}

func TestResolveRustLocalDeps_PathDependency(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "claw-server-rust")
	sharedDir := filepath.Join(root, "browseros-mcp")

	writeFile(t, filepath.Join(serverDir, "Cargo.toml"), `[package]
name = "browseros-claw-server-rs"

[dependencies]
browseros-mcp = { path = "../browseros-mcp" }
`)
	writeFile(t, filepath.Join(sharedDir, "Cargo.toml"), `[package]
name = "browseros-mcp"
`)

	server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
	shared, _ := newRustProject(filepath.Join(sharedDir, "Cargo.toml"))
	resolveRustLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveRustLocalDeps_WorkspaceTrueMatchingLocalCrateName(t *testing.T) {
	// Reproduces BrowserOS exactly: `browseros-mcp.workspace = true`, no
	// path, no bare version.
	root := t.TempDir()
	serverDir := filepath.Join(root, "claw-server-rust")
	sharedDir := filepath.Join(root, "browseros-mcp")

	writeFile(t, filepath.Join(serverDir, "Cargo.toml"), `[package]
name = "browseros-claw-server-rs"

[dependencies]
browseros-mcp.workspace = true
`)
	writeFile(t, filepath.Join(sharedDir, "Cargo.toml"), `[package]
name = "browseros-mcp"
`)

	server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
	shared, _ := newRustProject(filepath.Join(sharedDir, "Cargo.toml"))
	resolveRustLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveRustLocalDeps_GitDependencyIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared-lib")
	writeFile(t, filepath.Join(serverDir, "Cargo.toml"), `[package]
name = "server"

[dependencies]
shared-lib = { git = "https://github.com/x/shared-lib.git", branch = "main" }
`)
	writeFile(t, filepath.Join(sharedDir, "Cargo.toml"), `[package]
name = "shared-lib"
`)

	server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
	shared, _ := newRustProject(filepath.Join(sharedDir, "Cargo.toml"))
	resolveRustLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected a git dependency to never be treated as local even with a matching crate name, got %v", server.LocalDeps)
	}
}

func TestResolveRustLocalDeps_BareVersionIsNotLocalWithoutNameMatch(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	writeFile(t, filepath.Join(serverDir, "Cargo.toml"), `[package]
name = "server"

[dependencies]
serde = "1.0"
`)
	server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
	resolveRustLocalDeps([]*Project{server})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for a registry-only dependency with no local project of that name, got %v", server.LocalDeps)
	}
}
