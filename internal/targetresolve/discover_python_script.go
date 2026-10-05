package targetresolve

import (
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan"
)

// discoverLegacyPythonScripts walks repoRoot (same reposcan-exclude pruning
// as discoverProjects) looking for a standalone .py file with no enclosing
// pyproject.toml/setup.py, that at least textually mentions fastmcp or
// mcp.server/mcp.client (a cheap prefilter -- discovery finds candidates,
// classifyPythonScriptProject decides Role, the same discovery/
// classification separation this package already uses everywhere else).
// Reflects a real repo, oracle/mcp's dbtools-mcp-server.py, which has no
// pyproject.toml/setup.py anywhere in its directory tree at all -- just a
// README.md and requirements.txt alongside the script.
func discoverLegacyPythonScripts(repoRoot string) ([]*Project, error) {
	prune := &reposcan.Config{Root: repoRoot, ExcludedPaths: reposcan.DefaultConfig().ExcludedPaths}

	var candidates []*Project
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if prune.ShouldExclude(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".py") {
			return nil
		}

		dir := filepath.Dir(path)
		if hasEnclosingPythonManifest(dir, repoRoot) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil || !legacyPythonScriptPrefilterPattern.Match(data) {
			return nil
		}

		candidates = append(candidates, &Project{
			Name:         strings.TrimSuffix(info.Name(), ".py"),
			Dir:          dir,
			Ecosystem:    "python-script",
			ManifestPath: path, // the script itself; there is no manifest
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}

// hasEnclosingPythonManifest walks UP from dir to repoRoot (inclusive)
// checking each ancestor for pyproject.toml or setup.py -- independent of
// what discoverProjects already found, so a setup.py-based legacy package
// (out of scope for this feature) is also correctly excluded from this
// manifest-less special case, and a .py file nested several directories
// below a distant ancestor manifest is excluded too, not just an immediate
// sibling.
func hasEnclosingPythonManifest(dir, repoRoot string) bool {
	repoRoot = filepath.Clean(repoRoot)
	for cur := filepath.Clean(dir); ; {
		if fileExists(filepath.Join(cur, "pyproject.toml")) || fileExists(filepath.Join(cur, "setup.py")) {
			return true
		}
		if cur == repoRoot {
			return false
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// classifyPythonScriptProject re-reads the manifest-less script and
// requires the full combined-evidence chain before ever classifying it a
// server: construction/registration evidence (a FastMCP(...) call or a
// FastMCP subclass) OR the mcp.server namespace import, AND a __main__
// guard, AND a run/serve call. A partial match (e.g. only an import, no
// __main__ execution) is deliberately left RoleUnrelated -- avoids
// false-positiving every file that merely imports fastmcp for some
// unrelated reason (e.g. a test file exercising a real server elsewhere in
// the same directory).
func classifyPythonScriptProject(p *Project) (Role, []string) {
	data, err := os.ReadFile(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	hasNamespaceImport := pythonServerNamespaceImportPattern.Match(data)
	hasConstruction := pythonServerConstructionPattern.Match(data)
	hasMainGuard := pythonMainGuardPattern.Match(data)
	hasRunCall := pythonRunCallPattern.Match(data)

	if (hasConstruction || hasNamespaceImport) && hasMainGuard && hasRunCall {
		return RoleMCPServer, []string{
			"manifest-less Python script",
			"imports the MCP server namespace and/or constructs a server",
			"has a __main__ entrypoint that runs/serves it",
		}
	}
	if pythonClientNamespaceImportPattern.Match(data) || pythonClientConstructionPattern.Match(data) {
		return RoleMCPClient, []string{"manifest-less Python script; imports the MCP client namespace or constructs a client"}
	}
	if hasNamespaceImport || hasConstruction {
		return RoleUnrelated, []string{"manifest-less Python script mentions an MCP-related import/construction but lacks the full combined evidence (a __main__ entrypoint calling run()/serve()) required to classify it as a server"}
	}
	return RoleUnrelated, nil
}
