package targetresolve

import (
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan"
)

// manifestConstructors maps a manifest basename to the ecosystem-specific
// constructor that turns it into a Project. Ecosystems whose manifest
// filename is fixed (go.mod, package.json, pyproject.toml, pom.xml,
// Cargo.toml) are matched here by exact name. .csproj is handled separately
// in discoverProjects below (see newDotnetProject) because its filename
// varies per project (e.g. Fabric.Mcp.Server.csproj), so it can't be a map
// key. newRustProject can return (nil, nil) for a Cargo.toml that declares
// no [package] (a virtual workspace-root manifest) -- already tolerated by
// the `if project != nil` check below, same as any other constructor.
var manifestConstructors = map[string]func(manifestPath string) (*Project, error){
	"go.mod":         newGoProject,
	"package.json":   newNodeProject,
	"pyproject.toml": newPythonProject,
	"pom.xml":        newJavaProject,
	"Cargo.toml":     newRustProject,
}

// discoverProjects walks repoRoot looking for ecosystem manifest files and
// returns one Project per manifest found, with Role left unset (signals.go
// fills that in as a separate pass, once every project is known -- role
// classification for shared libraries depends on seeing every project, not
// just the one being visited).
//
// Reuses reposcan's default exclude list (config.go) so dependency caches --
// node_modules, .venv, vendor, .git, etc. -- are never descended into, the
// same pruning repo-scan's own SAST/secrets walkers already rely on. A
// directory can legitimately contain more than one nested project (e.g. a
// Python tool-definitions package living inside a larger Node monorepo), so
// finding a manifest does not stop the walk from continuing into
// subdirectories.
func discoverProjects(repoRoot string) ([]*Project, error) {
	prune := &reposcan.Config{
		Root:          repoRoot,
		ExcludedPaths: reposcan.DefaultConfig().ExcludedPaths,
	}

	var projects []*Project
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
		if info.IsDir() {
			return nil
		}

		constructor, ok := manifestConstructors[info.Name()]
		if !ok {
			if !strings.HasSuffix(info.Name(), ".csproj") {
				return nil
			}
			constructor = newDotnetProject
		}

		project, err := constructor(path)
		if err != nil {
			// A malformed manifest should not abort discovery of the rest of
			// the repository -- skip it, the same tolerance repo-scan's own
			// scanners already apply to unreadable/unparseable files.
			return nil
		}
		if project != nil {
			projects = append(projects, project)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return projects, nil
}
