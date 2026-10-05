package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestDiscoverRushWorkspace_ParsesProjectsArray(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rush.json"), `{
  "projects": [
    { "packageName": "@rushstack/mcp-server", "projectFolder": "apps/rush-mcp-server" },
    { "packageName": "@microsoft/api-extractor", "projectFolder": "apps/api-extractor" }
  ]
}`)

	projects, err := discoverRushWorkspace(root)
	if err != nil {
		t.Fatalf("discoverRushWorkspace returned error: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected 2 projects, got %d: %+v", len(projects), projects)
	}
	if projects[0].PackageName != "@rushstack/mcp-server" {
		t.Errorf("expected first project's PackageName to be @rushstack/mcp-server, got %q", projects[0].PackageName)
	}
	wantRoot := filepath.Join(root, "apps", "rush-mcp-server")
	if projects[0].Root != wantRoot {
		t.Errorf("expected Root %q, got %q", wantRoot, projects[0].Root)
	}
	if projects[0].DiscoverySource != "rush" {
		t.Errorf("expected DiscoverySource 'rush', got %q", projects[0].DiscoverySource)
	}
}

func TestDiscoverRushWorkspace_TolerantOfLineComments(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "rush.json"), `{
  // this is a comment
  "projects": [
    // another comment
    { "packageName": "@rushstack/mcp-server", "projectFolder": "apps/rush-mcp-server" } // trailing comment
  ]
}`)

	projects, err := discoverRushWorkspace(root)
	if err != nil {
		t.Fatalf("discoverRushWorkspace returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project despite comments, got %d: %+v", len(projects), projects)
	}
}

func TestDiscoverRushWorkspace_NoOpWithoutRushJSON(t *testing.T) {
	root := t.TempDir()
	projects, err := discoverRushWorkspace(root)
	if err != nil {
		t.Fatalf("discoverRushWorkspace returned error: %v", err)
	}
	if projects != nil {
		t.Errorf("expected nil when rush.json doesn't exist, got %+v", projects)
	}
}

func TestDiscoverLernaWorkspace_ParsesPackagesGlob(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lerna.json"), `{"packages": ["packages/*"]}`)

	patterns, err := discoverLernaWorkspace(root)
	if err != nil {
		t.Fatalf("discoverLernaWorkspace returned error: %v", err)
	}
	if len(patterns) != 1 || patterns[0] != "packages/*" {
		t.Errorf("expected [\"packages/*\"], got %v", patterns)
	}
}

func TestDiscoverPnpmWorkspace_ParsesGlobList(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - 'packages/*'\n")

	patterns, err := discoverPnpmWorkspace(root)
	if err != nil {
		t.Fatalf("discoverPnpmWorkspace returned error: %v", err)
	}
	if len(patterns) != 1 || patterns[0] != "packages/*" {
		t.Errorf("expected [\"packages/*\"], got %v", patterns)
	}
}

func TestDiscoverNxWorkspace_DetectsProjectJsonName(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "nx.json"), `{}`)
	projDir := filepath.Join(root, "packages", "my-server")
	writeFile(t, filepath.Join(projDir, "project.json"), `{"name": "my-server-nx-name"}`)

	p := &Project{Name: "my-server", Dir: projDir}
	result := discoverNxWorkspace(root, []*Project{p})
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d: %+v", len(result), result)
	}
	if result[0].PackageName != "my-server-nx-name" {
		t.Errorf("expected PackageName 'my-server-nx-name', got %q", result[0].PackageName)
	}
}

func TestDiscoverNxWorkspace_NoOpWithoutNxJson(t *testing.T) {
	root := t.TempDir()
	projDir := filepath.Join(root, "packages", "my-server")
	writeFile(t, filepath.Join(projDir, "project.json"), `{"name": "my-server-nx-name"}`)

	p := &Project{Name: "my-server", Dir: projDir}
	result := discoverNxWorkspace(root, []*Project{p})
	if result != nil {
		t.Errorf("expected nil without nx.json present, got %+v", result)
	}
}

func TestDiscoverTurborepoWorkspace_DetectionOnly(t *testing.T) {
	root := t.TempDir()
	if discoverTurborepoWorkspace(root) {
		t.Error("expected false when turbo.json doesn't exist")
	}
	writeFile(t, filepath.Join(root, "turbo.json"), `{}`)
	if !discoverTurborepoWorkspace(root) {
		t.Error("expected true once turbo.json exists")
	}
}

func TestApplyWorkspaceRegistrySignals_SetsWorkspaceSourcesWithoutClobberingEvidence(t *testing.T) {
	root := t.TempDir()
	projDir := filepath.Join(root, "apps", "rush-mcp-server")
	writeFile(t, filepath.Join(root, "rush.json"), `{
  "projects": [
    { "packageName": "@rushstack/mcp-server", "projectFolder": "apps/rush-mcp-server" }
  ]
}`)
	writeFile(t, filepath.Join(projDir, "package.json"), `{
		"name": "@rushstack/mcp-server",
		"dependencies": { "@modelcontextprotocol/sdk": "~1.10.2" }
	}`)
	writeFile(t, filepath.Join(projDir, "server.ts"), `
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
class RushMCPServer extends McpServer {}
`)

	p, _ := newNodeProject(filepath.Join(projDir, "package.json"))
	projects := []*Project{p}

	applyWorkspaceRegistrySignals(root, projects)
	classifyRoles(projects) // overwrites Evidence wholesale

	if len(p.WorkspaceSources) != 1 || p.WorkspaceSources[0] != "rush" {
		t.Errorf("expected WorkspaceSources to survive classifyRoles, got %v", p.WorkspaceSources)
	}
	if p.Role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v", p.Role)
	}
}

func TestApplyWorkspaceRegistrySignals_NeverOverridesARealPackageJSONName(t *testing.T) {
	root := t.TempDir()
	projDir := filepath.Join(root, "apps", "rush-mcp-server")
	writeFile(t, filepath.Join(root, "rush.json"), `{
  "projects": [
    { "packageName": "@rushstack/mcp-server-DIFFERENT-NAME", "projectFolder": "apps/rush-mcp-server" }
  ]
}`)
	writeFile(t, filepath.Join(projDir, "package.json"), `{"name": "my-real-package-json-name"}`)

	p, _ := newNodeProject(filepath.Join(projDir, "package.json"))
	applyWorkspaceRegistrySignals(root, []*Project{p})

	if p.Name != "my-real-package-json-name" {
		t.Errorf("expected the real package.json name to survive, got %q", p.Name)
	}
}
