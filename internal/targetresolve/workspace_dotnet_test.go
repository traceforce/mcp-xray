package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewDotnetProject(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Fabric.Mcp.Server.csproj")
	writeFile(t, manifest, `<Project Sdk="Microsoft.NET.Sdk"></Project>`)

	p, err := newDotnetProject(manifest)
	if err != nil {
		t.Fatalf("newDotnetProject returned error: %v", err)
	}
	if p.Name != "Fabric.Mcp.Server" {
		t.Errorf("expected name 'Fabric.Mcp.Server' (csproj basename minus extension), got %q", p.Name)
	}
	if p.Ecosystem != "dotnet" {
		t.Errorf("expected ecosystem 'dotnet', got %q", p.Ecosystem)
	}
	if p.Dir != root {
		t.Errorf("expected Dir %q, got %q", root, p.Dir)
	}
}

func TestResolveDotnetLocalDeps_RepoRootSubstitution(t *testing.T) {
	// Mirrors the real microsoft/mcp repo: a server's csproj references a
	// shared "core" project via $(RepoRoot), the common MSBuild convention
	// defined once in a root Directory.Build.props.
	root := t.TempDir()
	serverDir := filepath.Join(root, "servers", "Fabric.Mcp.Server", "src")
	coreDir := filepath.Join(root, "core", "Fabric.Mcp.Core", "src")

	writeFile(t, filepath.Join(serverDir, "Fabric.Mcp.Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="$(RepoRoot)\core\Fabric.Mcp.Core\src\Fabric.Mcp.Core.csproj" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(coreDir, "Fabric.Mcp.Core.csproj"), `<Project Sdk="Microsoft.NET.Sdk"></Project>`)

	server, err := newDotnetProject(filepath.Join(serverDir, "Fabric.Mcp.Server.csproj"))
	if err != nil {
		t.Fatalf("newDotnetProject(server) error: %v", err)
	}
	core, err := newDotnetProject(filepath.Join(coreDir, "Fabric.Mcp.Core.csproj"))
	if err != nil {
		t.Fatalf("newDotnetProject(core) error: %v", err)
	}

	projects := []*Project{server, core}
	resolveDotnetLocalDeps(root, projects)

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != core.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", core.Dir, server.LocalDeps)
	}
}

func TestResolveDotnetLocalDeps_Wildcard(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "servers", "Fabric.Mcp.Server", "src")
	toolADir := filepath.Join(root, "tools", "Fabric.Docs", "src")
	toolBDir := filepath.Join(root, "tools", "Fabric.OneLake", "src")

	writeFile(t, filepath.Join(serverDir, "Fabric.Mcp.Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="$(RepoRoot)\tools\Fabric.*\src\*.csproj" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(toolADir, "Fabric.Docs.csproj"), `<Project Sdk="Microsoft.NET.Sdk"></Project>`)
	writeFile(t, filepath.Join(toolBDir, "Fabric.OneLake.csproj"), `<Project Sdk="Microsoft.NET.Sdk"></Project>`)

	server, _ := newDotnetProject(filepath.Join(serverDir, "Fabric.Mcp.Server.csproj"))
	toolA, _ := newDotnetProject(filepath.Join(toolADir, "Fabric.Docs.csproj"))
	toolB, _ := newDotnetProject(filepath.Join(toolBDir, "Fabric.OneLake.csproj"))

	projects := []*Project{server, toolA, toolB}
	resolveDotnetLocalDeps(root, projects)

	if len(server.LocalDeps) != 2 {
		t.Fatalf("expected server.LocalDeps to contain both wildcard-matched tools, got %v", server.LocalDeps)
	}
	found := map[string]bool{}
	for _, dep := range server.LocalDeps {
		found[dep] = true
	}
	if !found[toolA.Dir] || !found[toolB.Dir] {
		t.Errorf("expected both %q and %q in server.LocalDeps, got %v", toolA.Dir, toolB.Dir, server.LocalDeps)
	}
}

func TestResolveDotnetLocalDeps_RelativePath(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "core", "Fabric.Mcp.Core", "src")
	sharedDir := filepath.Join(root, "core", "Microsoft.Mcp.Core", "src")

	writeFile(t, filepath.Join(serverDir, "Fabric.Mcp.Core.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\..\Microsoft.Mcp.Core\src\Microsoft.Mcp.Core.csproj" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(sharedDir, "Microsoft.Mcp.Core.csproj"), `<Project Sdk="Microsoft.NET.Sdk"></Project>`)

	fabricCore, _ := newDotnetProject(filepath.Join(serverDir, "Fabric.Mcp.Core.csproj"))
	msCore, _ := newDotnetProject(filepath.Join(sharedDir, "Microsoft.Mcp.Core.csproj"))

	projects := []*Project{fabricCore, msCore}
	resolveDotnetLocalDeps(root, projects)

	if len(fabricCore.LocalDeps) != 1 || fabricCore.LocalDeps[0] != msCore.Dir {
		t.Errorf("expected fabricCore.LocalDeps == [%q], got %v", msCore.Dir, fabricCore.LocalDeps)
	}
}

func TestResolveDotnetLocalDeps_UnresolvedPropertyIsSkippedNotGuessed(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")

	writeFile(t, filepath.Join(serverDir, "Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="$(SolutionDir)\shared\Shared.csproj" />
  </ItemGroup>
</Project>`)

	server, _ := newDotnetProject(filepath.Join(serverDir, "Server.csproj"))
	projects := []*Project{server}
	resolveDotnetLocalDeps(root, projects)

	if len(server.LocalDeps) != 0 {
		t.Errorf("expected no local deps for an unresolvable $(SolutionDir) property, got %v", server.LocalDeps)
	}
}

func TestDotnetPackageReferencePrefix(t *testing.T) {
	doc := &csprojFile{
		ItemGroups: []csprojItemGroup{
			{PackageReferences: []csprojRef{{Include: "ModelContextProtocol.AspNetCore"}}},
		},
	}
	if !dotnetPackageReferencePrefix(doc, "ModelContextProtocol") {
		t.Error("expected ModelContextProtocol.AspNetCore to match prefix ModelContextProtocol")
	}
	if dotnetPackageReferencePrefix(doc, "SomeOtherSDK") {
		t.Error("expected no match for an unrelated prefix")
	}
}
