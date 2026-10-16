package targetresolve

import (
	"os"
	"path/filepath"
	"strings"
)

// discoverLegacyPythonScripts finds standalone .py files with no enclosing
// pyproject.toml or setup.py that at least mention fastmcp or
// mcp.server/mcp.client -- a cheap prefilter; classifyPythonScriptProject
// decides the role. Some real servers ship as a bare script next to a
// requirements.txt, with no Python manifest at all.
func discoverLegacyPythonScripts(repoRoot string) ([]*Project, error) {
	var candidates []*Project
	enclosed := make(map[string]bool)
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		if !strings.HasSuffix(info.Name(), ".py") {
			return nil
		}
		dir := filepath.Dir(path)
		if hasEnclosingPythonManifest(dir, repoRoot, enclosed) {
			return nil
		}
		data, err := readFileCapped(path)
		if err != nil || !legacyPythonScriptPrefilterPattern.Match(data) {
			return nil
		}
		candidates = append(candidates, &Project{
			Name:         strings.TrimSuffix(info.Name(), ".py"),
			Dir:          dir,
			RelDir:       repoRelative(repoRoot, dir),
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
// checking each ancestor for a setup.py or a pyproject.toml that declares a
// project (declaresPythonProject) -- independent of what discoverProjects
// already found, so a setup.py-based legacy package (out of scope for this
// feature) is also correctly excluded from this manifest-less special case,
// and a .py file nested several directories below a distant ancestor
// manifest is excluded too, not just an immediate sibling. enclosed
// memoizes the answer per directory: without it, every .py file reparses
// each of its ancestors' pyproject.toml.
func hasEnclosingPythonManifest(dir, repoRoot string, enclosed map[string]bool) bool {
	dir = filepath.Clean(dir)
	if answer, ok := enclosed[dir]; ok {
		return answer
	}
	answer := declaresPythonProject(filepath.Join(dir, "pyproject.toml")) || fileExists(filepath.Join(dir, "setup.py"))
	if parent := filepath.Dir(dir); !answer && dir != filepath.Clean(repoRoot) && parent != dir {
		answer = hasEnclosingPythonManifest(parent, repoRoot, enclosed)
	}
	enclosed[dir] = answer
	return answer
}

// declaresPythonProject reports whether the pyproject.toml at path declares
// a package ([project] or [tool.poetry]). One holding only tool settings,
// such as a repository-wide [tool.ruff], packages nothing, so the scripts
// below it are still standalone.
func declaresPythonProject(path string) bool {
	doc, err := readPyprojectToml(path)
	if err != nil {
		return false
	}
	_, isProject := mapAt(doc, "project")
	_, isPoetry := mapAt(doc, "tool", "poetry")
	return isProject || isPoetry
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
	data, err := readFileCapped(p.ManifestPath)
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

// markEmbeddedScripts sets EmbeddedScript on every manifest-less script
// that lies inside the scan root of another project, one that
// ownsDirectory. A Python project around a script does not count: the
// script was found only because no Python manifest above it declares a
// package (hasEnclosingPythonManifest), so that one holds tool settings
// alone, such as a repository-wide [tool.ruff], and packages none of the
// files around the script. It runs once ownership roots are assigned.
func markEmbeddedScripts(projects []*Project) {
	for _, script := range projects {
		if ownsDirectory(script) {
			continue
		}
		for _, other := range projects {
			if ownsDirectory(other) && other.Ecosystem != "python" && within(script.Dir, other.ScanRoot()) {
				script.EmbeddedScript = true
				break
			}
		}
	}
}
