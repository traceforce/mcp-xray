package targetresolve

import (
	"path/filepath"
	"testing"
)

const validServerJSON = `{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "com.example/my-server",
  "packages": [
    { "registryType": "npm", "identifier": "@example/my-server", "transport": { "type": "stdio" } }
  ]
}`

func TestIsValidRegistryManifest(t *testing.T) {
	cases := []struct {
		name string
		doc  map[string]interface{}
		want bool
	}{
		{
			name: "valid with packages",
			doc:  map[string]interface{}{"name": "x", "packages": []interface{}{map[string]interface{}{}}},
			want: true,
		},
		{
			name: "valid with remotes",
			doc:  map[string]interface{}{"name": "x", "remotes": []interface{}{map[string]interface{}{}}},
			want: true,
		},
		{
			name: "missing name",
			doc:  map[string]interface{}{"packages": []interface{}{map[string]interface{}{}}},
			want: false,
		},
		{
			name: "missing packages and remotes",
			doc:  map[string]interface{}{"name": "x"},
			want: false,
		},
		{
			name: "empty packages array",
			doc:  map[string]interface{}{"name": "x", "packages": []interface{}{}},
			want: false,
		},
		{
			name: "unrelated file that happens to be named server.json",
			doc:  map[string]interface{}{"port": float64(8080), "host": "localhost"},
			want: false,
		},
		{
			name: "blank name",
			doc:  map[string]interface{}{"name": "", "packages": []interface{}{map[string]interface{}{}}},
			want: false,
		},
		{
			name: "whitespace-only name",
			doc:  map[string]interface{}{"name": "   ", "packages": []interface{}{map[string]interface{}{}}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidRegistryManifest(tc.doc); got != tc.want {
				t.Errorf("isValidRegistryManifest(%v) = %v, want %v", tc.doc, got, tc.want)
			}
		})
	}
}

func TestRegistryManifestDisplayName(t *testing.T) {
	cases := []struct {
		name          string
		doc           map[string]interface{}
		dir           string
		want          string
		wantConfirmed bool
	}{
		{"real name", map[string]interface{}{"name": "com.example/my-server"}, "/repo/servers/my-server", "com.example/my-server", true},
		{"unsubstituted template token", map[string]interface{}{"name": "<<McpRepositoryName>>"}, "/repo/servers/Fabric.Mcp.Server", "Fabric.Mcp.Server", false},
		{"empty name", map[string]interface{}{"name": ""}, "/repo/servers/Fabric.Mcp.Server", "Fabric.Mcp.Server", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, confirmed := registryManifestDisplayName(tc.doc, tc.dir)
			if got != tc.want {
				t.Errorf("registryManifestDisplayName(%v, %q) name = %q, want %q", tc.doc, tc.dir, got, tc.want)
			}
			if confirmed != tc.wantConfirmed {
				t.Errorf("registryManifestDisplayName(%v, %q) confirmed = %v, want %v", tc.doc, tc.dir, confirmed, tc.wantConfirmed)
			}
		})
	}
}

func TestApplyRegistryManifestSignals_UnconfirmedNameDoesNotClobberEcosystemName(t *testing.T) {
	// When the manifest's name is an unsubstituted placeholder, the
	// ecosystem-derived name (e.g. from a go.mod module path) should be kept
	// rather than overwritten with a plain directory-basename fallback.
	root := t.TempDir()
	serverDir := filepath.Join(root, "src") // deliberately uninformative dir name
	writeFile(t, filepath.Join(serverDir, "server.json"), `{
  "name": "<<McpRepositoryName>>",
  "packages": [ { "registryType": "npm", "identifier": "x" } ]
}`)

	existing := &Project{Name: "my-actual-server-name", Dir: serverDir, Ecosystem: "go", Role: RoleUnrelated}
	projects, err := applyRegistryManifestSignals(root, []*Project{existing})
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if existing.Name != "my-actual-server-name" {
		t.Errorf("expected the ecosystem-derived name to survive an unconfirmed manifest name, got %q", existing.Name)
	}
	if existing.Role != RoleMCPServer {
		t.Errorf("expected role still overridden to RoleMCPServer, got %v", existing.Role)
	}
}

func TestApplyRegistryManifestSignals_SynthesizesProjectForUnrecognizedEcosystem(t *testing.T) {
	// Reproduces the concrete .NET-shaped case: a directory with a valid
	// server.json and no ecosystem manifest this package can parse (no
	// go.mod/package.json/pyproject.toml/.csproj at all).
	root := t.TempDir()
	serverDir := filepath.Join(root, "servers", "my-server")
	writeFile(t, filepath.Join(serverDir, "server.json"), validServerJSON)

	projects, err := applyRegistryManifestSignals(root, nil)
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 synthesized project, got %d: %+v", len(projects), projects)
	}
	p := projects[0]
	if p.Role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v", p.Role)
	}
	if !p.RoleConfirmedByManifest {
		t.Error("expected RoleConfirmedByManifest to be true")
	}
	if p.Name != "com.example/my-server" {
		t.Errorf("expected name from manifest, got %q", p.Name)
	}
}

func TestApplyRegistryManifestSignals_OverridesExistingProjectRole(t *testing.T) {
	// A project a per-ecosystem heuristic would classify RoleUnrelated (no
	// SDK dependency at all) but which ships a valid server.json must end up
	// RoleMCPServer -- the universal signal overrides the ecosystem fallback.
	root := t.TempDir()
	serverDir := filepath.Join(root, "servers", "my-server")
	writeFile(t, filepath.Join(serverDir, "go.mod"), "module example.com/my-server\n\ngo 1.22\n")
	writeFile(t, filepath.Join(serverDir, "server.json"), validServerJSON)

	existing := &Project{Name: "my-server", Dir: serverDir, Ecosystem: "go", Role: RoleUnrelated}

	projects, err := applyRegistryManifestSignals(root, []*Project{existing})
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected the existing project to be reused, not duplicated; got %d projects", len(projects))
	}
	if existing.Role != RoleMCPServer {
		t.Errorf("expected existing project's role overridden to RoleMCPServer, got %v", existing.Role)
	}
	if !existing.RoleConfirmedByManifest {
		t.Error("expected RoleConfirmedByManifest to be true on the overridden project")
	}
}

func TestApplyRegistryManifestSignals_MalformedManifestIgnored(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "not-a-server", "server.json"), `{"unrelated": "config"}`)

	projects, err := applyRegistryManifestSignals(root, nil)
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("expected a malformed server.json to be ignored, got %d projects: %+v", len(projects), projects)
	}
}

func TestApplyRegistryManifestSignals_BlankNameManifestIgnored(t *testing.T) {
	// A server.json with a blank "name" is structurally malformed per the
	// registry schema (a real manifest always has a real name) and must not
	// promote its directory to RoleMCPServer, same as any other malformed
	// manifest (TestApplyRegistryManifestSignals_MalformedManifestIgnored).
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "not-a-server", "server.json"), `{
  "name": "",
  "packages": [ { "registryType": "npm", "identifier": "x" } ]
}`)

	projects, err := applyRegistryManifestSignals(root, nil)
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("expected a blank-name server.json to be ignored, got %d projects: %+v", len(projects), projects)
	}
}

func TestApplyRegistryManifestSignals_RemotesOnlyClassifiedAsRemoteReference(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "remote-server")
	writeFile(t, filepath.Join(serverDir, "server.json"), `{
  "name": "com.example/remote-server",
  "remotes": [ { "type": "streamable-http", "url": "https://example.com/mcp" } ]
}`)

	projects, err := applyRegistryManifestSignals(root, nil)
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 synthesized project, got %d: %+v", len(projects), projects)
	}
	p := projects[0]
	if p.Role != RoleRemoteReference {
		t.Errorf("expected RoleRemoteReference, got %v", p.Role)
	}
	if p.RoleConfirmedByManifest {
		t.Error("expected RoleConfirmedByManifest to be false for a remote reference")
	}
}

func TestApplyRegistryManifestSignals_RemotesOnlyOnExistingProjectDowngradesNotOverrides(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "remote-server")
	writeFile(t, filepath.Join(serverDir, "server.json"), `{
  "name": "com.example/remote-server",
  "remotes": [ { "type": "streamable-http", "url": "https://example.com/mcp" } ]
}`)

	existing := &Project{Name: "remote-server", Dir: serverDir, Ecosystem: "node", Role: RoleUnrelated}
	projects, err := applyRegistryManifestSignals(root, []*Project{existing})
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected the existing project to be reused, got %d projects", len(projects))
	}
	if existing.Role != RoleRemoteReference {
		t.Errorf("expected RoleRemoteReference, got %v", existing.Role)
	}
}

// A remotes-only manifest next to a project whose own source constructs a
// server (a local stdio proxy for a hosted server, say) leaves it a server:
// there is local code to scan.
func TestApplyRegistryManifestSignals_RemotesOnlyKeepsAProjectWithServerSource(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "proxy")
	writeFile(t, filepath.Join(serverDir, "server.json"), `{
  "name": "com.example/proxy",
  "remotes": [ { "type": "streamable-http", "url": "https://example.com/mcp" } ]
}`)
	existing := &Project{Name: "proxy", Dir: serverDir, Ecosystem: "node", Role: RoleMCPServer}
	if _, err := applyRegistryManifestSignals(root, []*Project{existing}); err != nil {
		t.Fatal(err)
	}
	if existing.Role != RoleMCPServer || existing.RoleConfirmedByManifest {
		t.Errorf("role = %v, confirmed = %v; want an unconfirmed server", existing.Role, existing.RoleConfirmedByManifest)
	}
}

// A server.json at a workspace root names the package that is the server;
// that package's project is what it describes, not the workspace root, and
// the root does not become everyone's ownership boundary.
func TestApplyRegistryManifestSignals_NamedPackageIsTheDescribedProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server.json"), `{
  "name": "com.example/server",
  "packages": [ { "registryType": "npm", "identifier": "@example/mcp-server" } ]
}`)
	workspace := &Project{Name: "example-monorepo", PackageName: "example-monorepo", Dir: root, RelDir: ".", Ecosystem: "node", Role: RoleUnrelated}
	server := &Project{Name: "@example/mcp-server", PackageName: "@example/mcp-server", Dir: filepath.Join(root, "packages", "server"), RelDir: "packages/server", Ecosystem: "node", Role: RoleUnrelated}
	other := &Project{Name: "@example/other", PackageName: "@example/other", Dir: filepath.Join(root, "packages", "other"), RelDir: "packages/other", Ecosystem: "node", Role: RoleMCPServer}
	projects := []*Project{workspace, server, other}

	if _, err := applyRegistryManifestSignals(root, projects); err != nil {
		t.Fatal(err)
	}
	if server.Role != RoleMCPServer || !server.RoleConfirmedByManifest || server.Name != "com.example/server" {
		t.Errorf("named package = %+v, want the confirmed server", server)
	}
	if workspace.Role != RoleUnrelated {
		t.Errorf("workspace root role = %v, want it left as classified", workspace.Role)
	}
	if isOwnershipBoundary(root, root, projects) {
		t.Error("a root server.json that names a nested package must not be an ownership boundary")
	}

	assignIdentities(root, projects)
	if other.ComponentID == server.ComponentID {
		t.Error("the other server must keep a component of its own")
	}
}

func TestRegistryManifestHit_PublishingProject(t *testing.T) {
	root := t.TempDir()
	py := &Project{Dir: filepath.Join(root, "py"), Ecosystem: "python", PackageName: "Weather_MCP.Server"}
	node := &Project{Dir: filepath.Join(root, "node"), Ecosystem: "node", PackageName: "@acme/weather"}
	nodeTwin := &Project{Dir: filepath.Join(root, "twin"), Ecosystem: "node", PackageName: "@acme/weather"}
	outside := &Project{Dir: filepath.Join(filepath.Dir(root), "elsewhere"), Ecosystem: "node", PackageName: "@acme/other"}
	pypi := registryManifestHit{Dir: root, Packages: []registryPackage{{RegistryType: "pypi", Identifier: "weather-mcp-server"}}}
	npm := registryManifestHit{Dir: root, Packages: []registryPackage{{RegistryType: "npm", Identifier: "@acme/weather"}}}
	if got := pypi.publishingProject([]*Project{py, node}); got != py {
		t.Errorf("PyPI names are compared PEP 503 normalized; got %+v", got)
	}
	if got := npm.publishingProject([]*Project{node, nodeTwin}); got != nil {
		t.Errorf("two projects publishing the package is ambiguous; got %+v", got)
	}
	other := registryManifestHit{Dir: root, Packages: []registryPackage{{RegistryType: "npm", Identifier: "@acme/other"}}}
	if got := other.publishingProject([]*Project{outside}); got != nil {
		t.Errorf("a project outside the manifest's directory is never described; got %+v", got)
	}
}

func TestReadRegistryManifest_SkipsPlaceholderPackages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"name": "x", "packages": [{"registryType": "nuget", "identifier": "<<DnxPackageId>>"}, {"registryType": "npm", "identifier": "@acme/x"}]}`)
	hit, ok := readRegistryManifest(dir, filepath.Join(dir, "server.json"))
	if !ok || !hit.HasLocalPackages || len(hit.Packages) != 1 || hit.Packages[0].Identifier != "@acme/x" {
		t.Errorf("hit = %+v, %v; want the npm package only", hit, ok)
	}
}

func TestApplyRegistryManifestSignals_DescendantServerJSONUpgradesNestedProject(t *testing.T) {
	// Reproduces the real microsoft/mcp shape: server.json sits one
	// directory above the actual manifest.
	root := t.TempDir()
	serverJSONDir := filepath.Join(root, "servers", "Fabric.Mcp.Server")
	csprojDir := filepath.Join(serverJSONDir, "src")
	writeFile(t, filepath.Join(serverJSONDir, "server.json"), validServerJSON)

	existing := &Project{Name: "Fabric.Mcp.Server", Dir: csprojDir, Ecosystem: "dotnet", Role: RoleUnrelated}
	projects, err := applyRegistryManifestSignals(root, []*Project{existing})
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected the nested project to be upgraded, not duplicated; got %d projects: %+v", len(projects), projects)
	}
	if existing.Role != RoleMCPServer {
		t.Errorf("expected the nested project to be upgraded to RoleMCPServer, got %v", existing.Role)
	}
	if !existing.RoleConfirmedByManifest {
		t.Error("expected RoleConfirmedByManifest to be true on the upgraded nested project")
	}
}

func TestApplyRegistryManifestSignals_DescendantSearchSkipsTestShapedSibling(t *testing.T) {
	root := t.TempDir()
	serverJSONDir := filepath.Join(root, "servers", "Fabric.Mcp.Server")
	realDir := filepath.Join(serverJSONDir, "src")
	testDir := filepath.Join(serverJSONDir, "Fabric.Mcp.Server.Tests")
	writeFile(t, filepath.Join(serverJSONDir, "server.json"), validServerJSON)

	real := &Project{Name: "Fabric.Mcp.Server", Dir: realDir, Ecosystem: "dotnet", Role: RoleUnrelated}
	testProj := &Project{Name: "Fabric.Mcp.Server.Tests", Dir: testDir, Ecosystem: "dotnet", Role: RoleMCPClient}
	projects, err := applyRegistryManifestSignals(root, []*Project{real, testProj})
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected the real project to be upgraded, not duplicated; got %d projects: %+v", len(projects), projects)
	}
	if real.Role != RoleMCPServer {
		t.Errorf("expected the real (non-test-shaped) project to be upgraded, got %v", real.Role)
	}
	if testProj.Role == RoleMCPServer {
		t.Errorf("expected the test-shaped sibling to never be the one upgraded, got %v", testProj.Role)
	}
}

func TestApplyRegistryManifestSignals_NoManifestsIsNoOp(t *testing.T) {
	root := t.TempDir()
	existing := []*Project{{Name: "x", Dir: filepath.Join(root, "x"), Role: RoleUnrelated}}

	projects, err := applyRegistryManifestSignals(root, existing)
	if err != nil {
		t.Fatalf("applyRegistryManifestSignals returned error: %v", err)
	}
	if len(projects) != 1 || projects[0].Role != RoleUnrelated {
		t.Errorf("expected projects unchanged when no server.json exists, got %+v", projects)
	}
}

// A server.json among tests, fixtures, documentation or examples is a sample
// of the format, not a description of a server in this repository.
func TestIsSampleManifestPath(t *testing.T) {
	cases := map[string]bool{
		"server.json":                        false,
		"servers/weather/server.json":        false,
		"packages/core/src/data/server.json": false,
		"test/fixtures/valid/server.json":    true,
		"docs/examples/server.json":          true,
		"examples/weather/server.json":       true,
		"src/Weather.Tests/server.json":      true,
		"pkg/weather_test/server.json":       true,
	}
	for relPath, want := range cases {
		if got := isSampleManifestPath(relPath); got != want {
			t.Errorf("isSampleManifestPath(%q) = %v, want %v", relPath, got, want)
		}
	}
}

func TestResolve_SampleServerJSONIsNotAServer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "my-mcp", "bin": {"my-mcp": "dist/index.js"}, "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
	writeFile(t, filepath.Join(root, "src", "index.ts"), `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; new McpServer();`)
	sample := `{"name": "io.example/fixture", "packages": [{"registryType": "npm", "identifier": "fixture-pkg"}]}`
	writeFile(t, filepath.Join(root, "test", "fixtures", "valid", "server.json"), sample)
	writeFile(t, filepath.Join(root, "docs", "examples", "server.json"), sample)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if names := targetNames(resolution.Targets); len(names) != 1 || names[0] != "my-mcp" {
		t.Errorf("targets = %v, want only my-mcp", names)
	}
}

// A server.json naming a package no project here publishes (a container
// image) above several independent servers describes one of them, but
// nothing says which: it neither merges them into one target nor becomes a
// server of its own, whether or not a workspace manifest sits beside it.
func TestResolve_UntiedManifestAboveSeveralServersOwnsNone(t *testing.T) {
	for name, workspaceRoot := range map[string]bool{"no root project": false, "workspace root project": true} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "server.json"), `{"name": "io.github.acme/a", "packages": [{"registryType": "oci", "identifier": "ghcr.io/acme/a:1.0"}]}`)
			if workspaceRoot {
				writeFile(t, filepath.Join(root, "package.json"), `{"name": "acme-servers", "private": true}`)
			}
			for _, server := range []string{"a", "b"} {
				dir := filepath.Join(root, "servers", server)
				writeFile(t, filepath.Join(dir, "package.json"), `{"name": "srv-`+server+`", "bin": "dist/index.js", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
				writeFile(t, filepath.Join(dir, "src", "index.ts"), `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; new McpServer();`)
			}

			resolution, err := Resolve(root)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			names := targetNames(resolution.Targets)
			if len(names) != 2 || len(resolution.Warnings) != 0 {
				t.Errorf("targets = %v, warnings = %v; want srv-a and srv-b, unambiguous", names, resolution.Warnings)
			}
			for _, p := range resolution.Projects {
				if p.RoleConfirmedByManifest {
					t.Errorf("%s confirmed by the root server.json, want none", p.Name)
				}
			}
		})
	}
}

// Several projects can share the manifest's directory; when its package
// names none of them, it describes the one that is a server by its own
// source, not whichever was discovered last.
func TestApplyRegistryManifestSignals_SharedDirectoryDescribesItsServer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server.json"), `{"name": "io.example/my-mcp", "packages": [{"registryType": "oci", "identifier": "ghcr.io/example/my-mcp"}]}`)
	server := &Project{Name: "my-mcp", Dir: root, RelDir: ".", Ecosystem: "node", Role: RoleMCPServer}
	tools := &Project{Name: "my-mcp-tools", Dir: root, RelDir: ".", Ecosystem: "python", Role: RoleUnrelated}

	if _, err := applyRegistryManifestSignals(root, []*Project{server, tools}); err != nil {
		t.Fatal(err)
	}
	if !server.RoleConfirmedByManifest || tools.Role != RoleUnrelated {
		t.Errorf("server confirmed = %v, tools role = %v; want the Node server confirmed and the Python tools untouched", server.RoleConfirmedByManifest, tools.Role)
	}
}

// A manifest whose directory holds several projects and no server cannot
// say which of them it describes: it confirms none, and stands for no
// server of its own either.
func TestApplyRegistryManifestSignals_SharedDirectoryWithoutAServerDescribesNone(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server.json"), `{"name": "io.example/my-mcp", "packages": [{"registryType": "oci", "identifier": "ghcr.io/example/my-mcp"}]}`)
	web := &Project{Name: "web", Dir: root, RelDir: ".", Ecosystem: "node", Role: RoleUnrelated}
	tools := &Project{Name: "tools", Dir: root, RelDir: ".", Ecosystem: "python", Role: RoleUnrelated}

	projects, err := applyRegistryManifestSignals(root, []*Project{web, tools})
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 || web.Role != RoleUnrelated || tools.Role != RoleUnrelated {
		t.Errorf("projects = %d, roles = %v, %v; want the two projects untouched and none synthesized", len(projects), web.Role, tools.Role)
	}
}
