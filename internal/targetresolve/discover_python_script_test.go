package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestDiscoverLegacyPythonScripts_OracleStyleStandaloneServer(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dbtools-mcp-server")
	writeFile(t, filepath.Join(dir, "README.md"), "# DBTools MCP Server\n")
	writeFile(t, filepath.Join(dir, "requirements.txt"), "fastmcp==3.4.2\n")
	writeFile(t, filepath.Join(dir, "dbtools-mcp-server.py"), `
from fastmcp import FastMCP

mcp = FastMCP("oci")

if __name__ == "__main__":
    mcp.run(transport='stdio')
`)

	projects, err := discoverLegacyPythonScripts(root)
	if err != nil {
		t.Fatalf("discoverLegacyPythonScripts returned error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(projects), projects)
	}

	role, evidence := classifyPythonScriptProject(projects[0])
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestDiscoverLegacyPythonScripts_SkipsFileInsideExistingPyprojectProject(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "normal-server")
	writeFile(t, filepath.Join(dir, "pyproject.toml"), "[project]\nname = \"normal-server\"\n")
	writeFile(t, filepath.Join(dir, "server.py"), `
from fastmcp import FastMCP
mcp = FastMCP("x")
if __name__ == "__main__":
    mcp.run()
`)

	projects, err := discoverLegacyPythonScripts(root)
	if err != nil {
		t.Fatalf("discoverLegacyPythonScripts returned error: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected a .py file next to pyproject.toml to be skipped, got %d: %+v", len(projects), projects)
	}
}

func TestDiscoverLegacyPythonScripts_SkipsFileNextToSetupPy(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "legacy-pkg")
	writeFile(t, filepath.Join(dir, "setup.py"), "from setuptools import setup\nsetup(name='legacy-pkg')\n")
	writeFile(t, filepath.Join(dir, "server.py"), `
from fastmcp import FastMCP
mcp = FastMCP("x")
if __name__ == "__main__":
    mcp.run()
`)

	projects, err := discoverLegacyPythonScripts(root)
	if err != nil {
		t.Fatalf("discoverLegacyPythonScripts returned error: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected a .py file next to setup.py to be skipped, got %d: %+v", len(projects), projects)
	}
}

func TestDiscoverLegacyPythonScripts_SkipsAncestorSetupPy(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "setup.py"), "from setuptools import setup\nsetup(name='root-pkg')\n")
	nested := filepath.Join(root, "src", "sub")
	writeFile(t, filepath.Join(nested, "server.py"), `
from fastmcp import FastMCP
mcp = FastMCP("x")
if __name__ == "__main__":
    mcp.run()
`)

	projects, err := discoverLegacyPythonScripts(root)
	if err != nil {
		t.Fatalf("discoverLegacyPythonScripts returned error: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected a .py file with an ancestor setup.py to be skipped, got %d: %+v", len(projects), projects)
	}
}

func TestClassifyPythonScriptProject_RequiresFullEvidenceCombination(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "unrelated-tool")
	scriptPath := filepath.Join(dir, "tool.py")
	writeFile(t, scriptPath, `
from fastmcp import FastMCP
# imports fastmcp but never constructs or runs anything
`)

	p := &Project{Name: "tool", Dir: dir, Ecosystem: "python-script", ManifestPath: scriptPath}
	role, evidence := classifyPythonScriptProject(p)
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated for partial evidence, got %v (evidence: %v)", role, evidence)
	}
}

func TestDiscoverLegacyPythonScripts_TestFileCoexistsWithRealScript(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dbtools-mcp-server")
	writeFile(t, filepath.Join(dir, "dbtools-mcp-server.py"), `
from fastmcp import FastMCP
mcp = FastMCP("oci")
if __name__ == "__main__":
    mcp.run(transport='stdio')
`)
	writeFile(t, filepath.Join(dir, "test_dbtools_mcp_server.py"), `
import fastmcp

def test_something():
    pass
`)

	projects, err := discoverLegacyPythonScripts(root)
	if err != nil {
		t.Fatalf("discoverLegacyPythonScripts returned error: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("expected 2 candidates (both .py files), got %d: %+v", len(projects), projects)
	}

	var serverRole, testRole Role
	for _, p := range projects {
		role, _ := classifyPythonScriptProject(p)
		if p.Name == "dbtools-mcp-server" {
			serverRole = role
		} else if p.Name == "test_dbtools_mcp_server" {
			testRole = role
		}
	}
	if serverRole != RoleMCPServer {
		t.Errorf("expected the real script to classify RoleMCPServer, got %v", serverRole)
	}
	if testRole == RoleMCPServer {
		t.Errorf("expected the test file (no __main__/run call) to not classify RoleMCPServer, got %v", testRole)
	}
}
