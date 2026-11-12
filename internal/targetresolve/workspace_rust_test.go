package targetresolve

import (
	"os"
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
	if !cargoHasDependency(doc, "rmcp", nil) {
		t.Error("expected cargoHasDependency to find rmcp even declared via workspace = true (no bare version)")
	}
	if cargoHasDependency(doc, "unrelated-crate", nil) {
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
	resolveRustLocalDeps(root, []*Project{server, shared})

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
	resolveRustLocalDeps(root, []*Project{server, shared})

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
	resolveRustLocalDeps(root, []*Project{server, shared})

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
	resolveRustLocalDeps(root, []*Project{server})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for a registry-only dependency with no local project of that name, got %v", server.LocalDeps)
	}
}

// The TOML key of a Cargo dependency is only the name it is imported under;
// the "package" key -- on the entry itself or on the workspace definition it
// inherits -- names the crate actually depended on.
func TestResolveRustLocalDeps_RenamedDependencies(t *testing.T) {
	cases := []struct {
		name          string
		workspaceToml string // root Cargo.toml; "" for none
		serverDeps    string
		want          string // "shared", "other" or "" for no edge
	}{
		{"inline rename", "", `local = { package = "shared-lib", version = "0.1" }`, "shared"},
		{"inline rename with workspace = true and no workspace definition", "", `local = { package = "shared-lib", workspace = true }`, "shared"},
		{"key naming a local crate is not the dependency when renamed", "", `shared-lib = { package = "other-crate", version = "1" }`, "other"},
		{"rename inherited from [workspace.dependencies]", `[workspace]
members = ["server", "crates/*"]

[workspace.dependencies]
local = { package = "shared-lib", version = "0.1" }
`, `local = { workspace = true }`, "shared"},
		{"path inherited from [workspace.dependencies] is relative to the workspace root", `[workspace]
members = ["server", "crates/*"]

[workspace.dependencies]
renamed = { path = "crates/shared" }
`, `renamed.workspace = true`, "shared"},
		{"git inherited from [workspace.dependencies] is never local", `[workspace]
members = ["server", "crates/*"]

[workspace.dependencies]
shared-lib = { git = "https://github.com/x/shared-lib.git" }
`, `shared-lib.workspace = true`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			serverDir := filepath.Join(root, "server")
			dirs := map[string]string{
				"shared": filepath.Join(root, "crates", "shared"),
				"other":  filepath.Join(root, "crates", "other"),
			}
			if tc.workspaceToml != "" {
				writeFile(t, filepath.Join(root, "Cargo.toml"), tc.workspaceToml)
			}
			writeFile(t, filepath.Join(serverDir, "Cargo.toml"), "[package]\nname = \"server\"\n\n[dependencies]\n"+tc.serverDeps+"\n")
			writeFile(t, filepath.Join(dirs["shared"], "Cargo.toml"), "[package]\nname = \"shared-lib\"\n")
			writeFile(t, filepath.Join(dirs["other"], "Cargo.toml"), "[package]\nname = \"other-crate\"\n")

			var projects []*Project
			for _, dir := range []string{serverDir, dirs["shared"], dirs["other"]} {
				project, err := newRustProject(filepath.Join(dir, "Cargo.toml"))
				if err != nil || project == nil {
					t.Fatalf("newRustProject(%s) = %v, %v", dir, project, err)
				}
				projects = append(projects, project)
			}
			resolveRustLocalDeps(root, projects)

			server := projects[0]
			if tc.want == "" {
				if len(server.LocalDeps) != 0 {
					t.Errorf("LocalDeps = %v, want none", server.LocalDeps)
				}
				return
			}
			if len(server.LocalDeps) != 1 || server.LocalDeps[0] != dirs[tc.want] {
				t.Errorf("LocalDeps = %v, want [%s]", server.LocalDeps, dirs[tc.want])
			}
		})
	}
}

// A Cargo.toml above the repository root must never be read as the
// workspace: the repository is the boundary of what gets analyzed.
func TestResolveRustLocalDeps_WorkspaceLookupStaysInsideRepo(t *testing.T) {
	outer := t.TempDir()
	writeFile(t, filepath.Join(outer, "Cargo.toml"), `[workspace]

[workspace.dependencies]
local = { package = "shared-lib" }
`)
	root := filepath.Join(outer, "repo")
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")
	writeFile(t, filepath.Join(serverDir, "Cargo.toml"), "[package]\nname = \"server\"\n\n[dependencies]\nlocal.workspace = true\n")
	writeFile(t, filepath.Join(sharedDir, "Cargo.toml"), "[package]\nname = \"shared-lib\"\n")

	server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
	shared, _ := newRustProject(filepath.Join(sharedDir, "Cargo.toml"))
	resolveRustLocalDeps(root, []*Project{server, shared})

	if len(server.LocalDeps) != 0 {
		t.Errorf("LocalDeps = %v, want none (the only workspace definition is outside the repository)", server.LocalDeps)
	}
}

// A package.workspace path through a symlinked directory, or a symlinked
// Cargo.toml, must not let the resolver read a manifest outside the repo.
func TestResolveRustLocalDeps_WorkspaceLookupDoesNotFollowSymlinksOutOfRepo(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "Cargo.toml"), `[workspace]

[workspace.dependencies]
local = { package = "shared-lib" }
`)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string) (serverManifest string)
	}{
		{"package.workspace through a symlinked directory", func(t *testing.T, root string) string {
			if err := os.Symlink(outside, filepath.Join(root, "ws")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			return "[package]\nname = \"server\"\nworkspace = \"../ws\"\n\n[dependencies]\nlocal.workspace = true\n"
		}},
		{"symlinked Cargo.toml in an ancestor", func(t *testing.T, root string) string {
			if err := os.Symlink(filepath.Join(outside, "Cargo.toml"), filepath.Join(root, "Cargo.toml")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			return "[package]\nname = \"server\"\n\n[dependencies]\nlocal.workspace = true\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			serverDir := filepath.Join(root, "server")
			sharedDir := filepath.Join(root, "shared")
			writeFile(t, filepath.Join(serverDir, "Cargo.toml"), tc.setup(t, root))
			writeFile(t, filepath.Join(sharedDir, "Cargo.toml"), "[package]\nname = \"shared-lib\"\n")

			server, _ := newRustProject(filepath.Join(serverDir, "Cargo.toml"))
			shared, _ := newRustProject(filepath.Join(sharedDir, "Cargo.toml"))
			resolveRustLocalDeps(root, []*Project{server, shared})

			if len(server.LocalDeps) != 0 {
				t.Errorf("LocalDeps = %v, want none (the only workspace definition is outside the repository)", server.LocalDeps)
			}
		})
	}
}

func TestCargoHasDependency_RenamedSDK(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	writeFile(t, manifest, `[package]
name = "server"

[dependencies]
mcp = { package = "rmcp", version = "0.8" }
rmcp-like = { package = "not-rmcp", version = "1" }
`)
	doc, err := readCargoToml(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !cargoHasDependency(doc, "rmcp", nil) {
		t.Error("expected a dependency renamed from rmcp to count as the rmcp SDK")
	}
	if cargoHasDependency(doc, "rmcp-like", nil) {
		t.Error("expected a key whose real package is not-rmcp to not count under its key")
	}
}

// A rename that lives only in the workspace root's [workspace.dependencies]
// must still identify the SDK, end to end through Resolve -- the shape of a
// server built inside an rmcp-style Cargo workspace.
func TestResolve_RustServerWithWorkspaceRenamedSDK(t *testing.T) {
	// Source code refers to a renamed crate by its new name, so both the
	// bare-trait and the path-qualified impl forms must be recognized.
	for name, source := range map[string]string{
		"use, then bare impl": "use mcp::ServerHandler;\nstruct S;\nimpl ServerHandler for S {}\nfn main() {}\n",
		"path-qualified impl": "struct S;\nimpl mcp::handler::server::ServerHandler for S {}\nfn main() {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "Cargo.toml"), `[workspace]
members = ["server"]

[workspace.dependencies]
mcp = { package = "rmcp", version = "0.8" }
`)
			writeFile(t, filepath.Join(root, "server", "Cargo.toml"), `[package]
name = "my-server"

[dependencies]
mcp.workspace = true
`)
			writeFile(t, filepath.Join(root, "server", "src", "main.rs"), source)

			resolution, err := Resolve(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolution.Targets) != 1 || resolution.Targets[0].Name != "my-server" {
				var names []string
				for _, target := range resolution.Targets {
					names = append(names, target.Name)
				}
				t.Fatalf("targets = %v, want [my-server]", names)
			}
		})
	}
}

func TestProjectRepoRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	cases := []struct {
		dir, relDir string
		want        string
		ok          bool
	}{
		{root, ".", root, true},
		{filepath.Join(root, "server"), "server", root, true},
		{filepath.Join(root, "a", "b", "c"), "a/b/c", root, true},
		{filepath.Join(root, "x"), "", "", false},
	}
	for _, tc := range cases {
		got, ok := projectRepoRoot(&Project{Dir: tc.dir, RelDir: tc.relDir})
		if got != tc.want || ok != tc.ok {
			t.Errorf("projectRepoRoot(%q, %q) = %q, %v; want %q, %v", tc.dir, tc.relDir, got, ok, tc.want, tc.ok)
		}
	}
}
