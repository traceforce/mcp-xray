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
