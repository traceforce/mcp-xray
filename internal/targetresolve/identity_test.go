package targetresolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsOwnershipBoundary_ValidServerJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), validServerJSON)
	if !isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected a valid server.json to be recognized as an ownership boundary")
	}
}

func TestIsOwnershipBoundary_UnrelatedFileNamedServerJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"port": 8080, "host": "localhost"}`)
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected an unrelated file merely named server.json to NOT be an ownership boundary")
	}
}

func TestIsOwnershipBoundary_BlankNameServerJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"name": "", "packages": [{"registryType": "npm", "identifier": "x"}]}`)
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected a blank-name server.json to NOT be an ownership boundary")
	}
}

func TestIsOwnershipBoundary_ComponentJSONAloneIsNotABoundary(t *testing.T) {
	// component.json is the Bower package manifest, unrelated to MCP.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "component.json"), `{"name": "some-bower-package"}`)
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected component.json alone to NOT be an ownership boundary")
	}
}

func TestIsOwnershipBoundary_NoFile(t *testing.T) {
	dir := t.TempDir()
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected a directory with neither file to NOT be an ownership boundary")
	}
}

func TestIsOwnershipBoundary_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{not valid json`)
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("expected malformed JSON to NOT be an ownership boundary")
	}
}

// Two independent projects under a common ancestor that holds an unrelated
// file named server.json keep separate ComponentIDs (and so remain two
// targets) rather than being collapsed into one.
func TestAssignIdentities_UnrelatedServerJSONDoesNotMergeIndependentServers(t *testing.T) {
	root := t.TempDir()
	platformDir := filepath.Join(root, "platform")
	writeFile(t, filepath.Join(platformDir, "server.json"), `{"unrelated": "config"}`)

	serverADir := filepath.Join(platformDir, "server-a")
	serverBDir := filepath.Join(platformDir, "server-b")
	if err := os.MkdirAll(serverADir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server-a) failed: %v", err)
	}
	if err := os.MkdirAll(serverBDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server-b) failed: %v", err)
	}

	serverA := &Project{Name: "server-a", Dir: serverADir, Ecosystem: "node", Role: RoleMCPServer}
	serverB := &Project{Name: "server-b", Dir: serverBDir, Ecosystem: "node", Role: RoleMCPServer}

	assignIdentities(root, []*Project{serverA, serverB})

	if serverA.ComponentID == serverB.ComponentID {
		t.Errorf("expected server-a and server-b to have distinct ComponentIDs (the unrelated platform/server.json must not merge them), got the same ComponentID %q for both", serverA.ComponentID)
	}
	if serverA.OwnershipRoot != filepath.Clean(serverADir) {
		t.Errorf("expected server-a's ownership root to remain its own directory, got %q", serverA.OwnershipRoot)
	}
	if serverB.OwnershipRoot != filepath.Clean(serverBDir) {
		t.Errorf("expected server-b's ownership root to remain its own directory, got %q", serverB.OwnershipRoot)
	}
}

// A real registry manifest one directory above a project makes that
// directory the project's ownership root, so projects that belong together
// (a .NET server and a client packaged alongside it) share one component.
func TestAssignIdentities_ValidServerJSONStillMergesSiblingProjects(t *testing.T) {
	root := t.TempDir()
	componentDir := filepath.Join(root, "my-component")
	writeFile(t, filepath.Join(componentDir, "server.json"), validServerJSON)

	serverDir := filepath.Join(componentDir, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server) failed: %v", err)
	}

	server := &Project{Name: "server", Dir: serverDir, Ecosystem: "node", Role: RoleMCPServer}
	assignIdentities(root, []*Project{server})

	if server.OwnershipRoot != filepath.Clean(componentDir) {
		t.Errorf("expected ownership root to be promoted to the valid server.json's directory %q, got %q", componentDir, server.OwnershipRoot)
	}
}

// Discovery walks the tree in lexical order, so a server's dependencies can
// be discovered both before (a-lib) and after (z-lib) the server itself.
// Every dependency must get its real stable ID and stay in the target's
// scope: a single empty ID once dropped z-lib while a-lib kept the scope
// looking healthy.
func TestResolve_DependencyDiscoveredAfterItsDependentStaysInScope(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "server",
		"dependencies": {"@modelcontextprotocol/sdk": "^1", "a-lib": "workspace:*", "z-lib": "workspace:*"}
	}`)
	writeFile(t, filepath.Join(root, "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	writeFile(t, filepath.Join(root, "a-lib", "package.json"), `{"name": "a-lib"}`)
	writeFile(t, filepath.Join(root, "z-lib", "package.json"), `{"name": "z-lib"}`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range resolution.Projects {
		for _, id := range p.LocalDepIDs {
			if id == "" {
				t.Errorf("project %s has an empty LocalDepIDs entry: %v", p.Name, p.LocalDepIDs)
			}
		}
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(resolution.Targets))
	}
	included := map[string]bool{}
	for _, p := range resolution.Targets[0].Included {
		included[p.Name] = true
	}
	if !included["a-lib"] || !included["z-lib"] {
		t.Errorf("target scope = %v, want both a-lib and z-lib included", included)
	}
}

// A manifest that only points at a hosted server describes no local code,
// so it does not group the projects below it into one component.
func TestIsOwnershipBoundary_RemotesOnlyManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"name": "com.example/hosted", "remotes": [{"type": "streamable-http", "url": "https://example.com/mcp"}]}`)
	if isOwnershipBoundary(dir, dir, nil) {
		t.Error("a remotes-only server.json must not be an ownership boundary")
	}
}

// A project whose own directory holds its server.json owns that directory,
// even inside an outer boundary, so the projects below it belong to it
// rather than the other way round.
func TestAssignIdentities_NestedServerJSONOwnsItsOwnDirectory(t *testing.T) {
	root := t.TempDir()
	outer, inner, nested := filepath.Join(root, "pkg"), filepath.Join(root, "pkg", "sub"), filepath.Join(root, "pkg", "sub", "x")
	writeFile(t, filepath.Join(outer, "server.json"), validServerJSON)
	writeFile(t, filepath.Join(inner, "server.json"), validServerJSON)
	server := &Project{Name: "sub", Dir: inner, Ecosystem: "node", Role: RoleMCPServer}
	tool := &Project{Name: "x", Dir: nested, Ecosystem: "node"}

	assignIdentities(root, []*Project{server, tool})

	if server.OwnershipRoot != filepath.Clean(inner) || tool.OwnershipRoot != filepath.Clean(inner) {
		t.Errorf("ownership roots = %q, %q; want both %q", server.OwnershipRoot, tool.OwnershipRoot, inner)
	}
}

// A repository with nothing to list still lists every collection, empty, so
// a consumer can iterate them without a null check.
func TestResolutionJSON_EmptyListsAreArrays(t *testing.T) {
	data, err := ResolutionJSON(&Resolution{RepoRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var view map[string]json.RawMessage
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"projects", "components", "targets", "inventory"} {
		if got := string(view[key]); got != "[]" {
			t.Errorf("%s = %s, want []", key, got)
		}
	}
}
