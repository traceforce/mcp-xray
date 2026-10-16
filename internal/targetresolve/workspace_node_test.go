package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewNodeProject(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	writeFile(t, manifest, `{"name": "my-node-server"}`)

	p, err := newNodeProject(manifest)
	if err != nil {
		t.Fatalf("newNodeProject returned error: %v", err)
	}
	if p.Name != "my-node-server" {
		t.Errorf("expected name 'my-node-server', got %q", p.Name)
	}
	if p.Ecosystem != "node" {
		t.Errorf("expected ecosystem 'node', got %q", p.Ecosystem)
	}
}

func TestNewNodeProject_FallsBackToDirNameWhenUnnamed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "unnamed-pkg")
	manifest := filepath.Join(dir, "package.json")
	writeFile(t, manifest, `{}`)

	p, err := newNodeProject(manifest)
	if err != nil {
		t.Fatalf("newNodeProject returned error: %v", err)
	}
	if p.Name != "unnamed-pkg" {
		t.Errorf("expected fallback name 'unnamed-pkg', got %q", p.Name)
	}
}

func TestResolveNodeLocalDeps_WorkspaceProtocol(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "server",
		"dependencies": { "shared-lib": "workspace:*" }
	}`)
	writeFile(t, filepath.Join(sharedDir, "package.json"), `{"name": "shared-lib"}`)

	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	shared, _ := newNodeProject(filepath.Join(sharedDir, "package.json"))
	projects := []*Project{server, shared}
	resolveNodeLocalDeps(projects)

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveNodeLocalDeps_FileProtocol(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "server",
		"devDependencies": { "shared-lib": "file:../shared" }
	}`)
	writeFile(t, filepath.Join(sharedDir, "package.json"), `{"name": "shared-lib"}`)

	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	shared, _ := newNodeProject(filepath.Join(sharedDir, "package.json"))
	resolveNodeLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveNodeLocalDeps_RegistryDependencyIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "server",
		"dependencies": { "express": "^4.18.0" }
	}`)
	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	resolveNodeLocalDeps([]*Project{server})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for a registry dependency, got %v", server.LocalDeps)
	}
}

func TestResolveNodeLocalDeps_PlainVersionMatchingLocalPackageName(t *testing.T) {
	// Reproduces twilio-labs/mcp exactly: @twilio-alpha/mcp depends on its
	// sibling via a plain version string, no workspace:/file:/link: protocol
	// at all.
	root := t.TempDir()
	serverDir := filepath.Join(root, "mcp")
	sharedDir := filepath.Join(root, "openapi-mcp-server")

	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "@twilio-alpha/mcp",
		"dependencies": { "@twilio-alpha/openapi-mcp-server": "0.7.0" }
	}`)
	writeFile(t, filepath.Join(sharedDir, "package.json"), `{"name": "@twilio-alpha/openapi-mcp-server"}`)

	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	shared, _ := newNodeProject(filepath.Join(sharedDir, "package.json"))
	resolveNodeLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolveNodeLocalDeps_NpmAliasIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared-lib")
	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "server",
		"dependencies": { "shared-lib": "npm:other-package@1.0.0" }
	}`)
	writeFile(t, filepath.Join(sharedDir, "package.json"), `{"name": "shared-lib"}`)

	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	shared, _ := newNodeProject(filepath.Join(sharedDir, "package.json"))
	resolveNodeLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected an npm: alias to never be treated as local, got %v", server.LocalDeps)
	}
}

func TestResolveNodeLocalDeps_GitURLIsNotLocal(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared-lib")
	writeFile(t, filepath.Join(serverDir, "package.json"), `{
		"name": "server",
		"dependencies": { "shared-lib": "git+https://github.com/x/shared-lib.git" }
	}`)
	writeFile(t, filepath.Join(sharedDir, "package.json"), `{"name": "shared-lib"}`)

	server, _ := newNodeProject(filepath.Join(serverDir, "package.json"))
	shared, _ := newNodeProject(filepath.Join(sharedDir, "package.json"))
	resolveNodeLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected a git URL to never be treated as local, got %v", server.LocalDeps)
	}
}

func TestNewNodeProject_BinStringForm(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	writeFile(t, manifest, `{"name": "@scope/my-server", "bin": "./bin/my-server"}`)

	p, err := newNodeProject(manifest)
	if err != nil {
		t.Fatalf("newNodeProject returned error: %v", err)
	}
	if len(p.BinNames) != 1 || p.BinNames[0] != "my-server" {
		t.Errorf("expected BinNames == [\"my-server\"], got %v", p.BinNames)
	}
}

func TestNewNodeProject_BinObjectForm(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	writeFile(t, manifest, `{"name": "my-server", "bin": {"foo": "./a", "bar": "./b"}}`)

	p, err := newNodeProject(manifest)
	if err != nil {
		t.Fatalf("newNodeProject returned error: %v", err)
	}
	if len(p.BinNames) != 2 || p.BinNames[0] != "bar" || p.BinNames[1] != "foo" {
		t.Errorf("expected sorted BinNames == [\"bar\", \"foo\"], got %v", p.BinNames)
	}
}

func TestNewNodeProject_NoBinField(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "package.json")
	writeFile(t, manifest, `{"name": "my-server"}`)

	p, err := newNodeProject(manifest)
	if err != nil {
		t.Fatalf("newNodeProject returned error: %v", err)
	}
	if p.BinNames != nil {
		t.Errorf("expected nil BinNames when no bin field is present, got %v", p.BinNames)
	}
}

// pnpm's workspace: protocol can name the sibling in the spec itself -- as an
// alias or a relative path -- in which case the dependency key is only the
// local import name and must not be what decides the edge.
func TestResolveNodeLocalDeps_WorkspaceProtocolSpecs(t *testing.T) {
	cases := []struct {
		name    string
		depKey  string
		depSpec string
		want    string // which sibling the edge must point at ("" for none)
	}{
		{"plain range uses the key", "real-pkg", "workspace:*", "real"},
		{"unscoped alias", "local-name", "workspace:real-pkg@*", "real"},
		{"scoped alias", "local-name", "workspace:@scope/scoped-pkg@^1.0.0", "scoped"},
		{"relative path", "local-name", "workspace:../real", "real"},
		{"relative path below the project", "local-name", "workspace:./vendor-local", "nested"},
		{"alias wins over a key naming another sibling", "real-pkg", "workspace:@scope/scoped-pkg@*", "scoped"},
		{"unresolvable alias never falls back to the key", "real-pkg", "workspace:not-in-repo@*", ""},
		{"unresolvable path never falls back to the key", "real-pkg", "workspace:../missing", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			serverDir := filepath.Join(root, "server")
			dirs := map[string]string{
				"real":   filepath.Join(root, "real"),
				"scoped": filepath.Join(root, "scoped"),
				"nested": filepath.Join(serverDir, "vendor-local"),
			}
			writeFile(t, filepath.Join(serverDir, "package.json"), `{"name": "server", "dependencies": {"`+tc.depKey+`": "`+tc.depSpec+`"}}`)
			writeFile(t, filepath.Join(dirs["real"], "package.json"), `{"name": "real-pkg"}`)
			writeFile(t, filepath.Join(dirs["scoped"], "package.json"), `{"name": "@scope/scoped-pkg"}`)
			writeFile(t, filepath.Join(dirs["nested"], "package.json"), `{"name": "nested-pkg"}`)

			var projects []*Project
			for _, dir := range []string{serverDir, dirs["real"], dirs["scoped"], dirs["nested"]} {
				project, err := newNodeProject(filepath.Join(dir, "package.json"))
				if err != nil {
					t.Fatal(err)
				}
				projects = append(projects, project)
			}
			resolveNodeLocalDeps(projects)

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

// npm allows non-string "scripts" values such as its "//" comments; they
// must not make a package unreadable and drop it from discovery.
func TestNewNodeProject_NonStringScriptValues(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name": "server", "scripts": {"//": ["start with npm start"], "start": "node index.js"}}`)
	if p, err := newNodeProject(filepath.Join(dir, "package.json")); err != nil || p.Name != "server" {
		t.Errorf("newNodeProject = %+v, %v; want the server project", p, err)
	}
}

// A package.json without a "name" is no package a dependency can name,
// whatever its directory is called: the server's registry dependency on
// hono is not the unnamed examples/hono app.
func TestResolveNodeLocalDeps_UnnamedPackageIsNotADependency(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "package.json"), `{"name": "my-mcp", "dependencies": {"hono": "^4.0.0"}}`)
	writeFile(t, filepath.Join(root, "examples", "hono", "package.json"), `{"private": true, "dependencies": {"hono": "^4.0.0"}}`)

	server, _ := newNodeProject(filepath.Join(root, "server", "package.json"))
	example, _ := newNodeProject(filepath.Join(root, "examples", "hono", "package.json"))
	resolveNodeLocalDeps([]*Project{server, example})

	if len(server.LocalDeps) != 0 {
		t.Errorf("server.LocalDeps = %v, want none", server.LocalDeps)
	}
}
