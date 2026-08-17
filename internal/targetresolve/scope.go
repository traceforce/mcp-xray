package targetresolve

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mcpxray/internal/reposcan"
)

// PrimaryRoot returns the selected server project's own directory
// (cleaned), used to distinguish "direct" findings from "shared-dependency"
// findings when tagging scan results.
func (t *Target) PrimaryRoot() string {
	return filepath.Clean(t.Project.Dir)
}

// ScanRoots returns the directories that must be scanned together for this
// target: the primary project's directory plus every included shared
// component's directory, deduplicated, with any root that is nested inside
// another already-included root dropped so the same files are never handed
// to the underlying scanners twice.
func (t *Target) ScanRoots() []string {
	var dirs []string
	seen := make(map[string]bool)
	for _, p := range t.Included {
		dir := filepath.Clean(p.OwnershipRoot)
		if p.OwnershipRoot == "" {
			dir = filepath.Clean(p.Dir)
		}
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}

	return dropNestedRoots(dirs)
}

// manifestAndLockfilePatterns is the list of file basenames (some
// wildcarded) DiscoveredManifests recognizes across all 6 supported
// ecosystems. Purely informational: this list is never consulted by the
// underlying SCA scanner (internal/reposcan/sca.go), which still receives
// only a directory Root and does its own independent, ecosystem-agnostic
// manifest discovery via osv-scanner's recursive walk (see sca.go's
// DirectoryPaths/Recursive:true). This exists so callers like --list-targets
// can show which dependency files a target's scope actually contains.
var manifestAndLockfilePatterns = []string{
	"go.mod", "go.sum",
	"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
	"pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "requirements*.txt", "setup.py",
	"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
	"Cargo.toml", "Cargo.lock",
	"*.csproj", "packages.lock.json",
}

// DiscoveredManifests walks roots (typically a Target's ScanRoots()) and
// returns every file path matching manifestAndLockfilePatterns, sorted and
// deduplicated. Reuses the same reposcan.DefaultConfig().ExcludedPaths
// pruning already used throughout this package (e.g. discoverProjects,
// projectSourceSignals) so dependency caches are never descended into.
// Overlapping/nested roots are handled safely: results are deduplicated by
// cleaned path regardless of which root found them first.
func DiscoveredManifests(roots []string) []string {
	var found []string
	seen := make(map[string]bool)

	for _, root := range roots {
		// Manifest/lockfile discovery is an SCA diagnostic stage. Keep
		// dependency files visible even though the legacy SAST/secrets default
		// exclusions include some lockfile names.
		prune := &reposcan.Config{Root: root, ExcludedPaths: directoryDiscoveryExcludes()}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
			if !matchesAnyManifestPattern(info.Name()) {
				return nil
			}
			cleaned := filepath.Clean(path)
			if !seen[cleaned] {
				seen[cleaned] = true
				found = append(found, cleaned)
			}
			return nil
		})
	}

	sort.Strings(found)
	return found
}

func directoryDiscoveryExcludes() []string {
	result := make([]string, 0)
	for _, value := range reposcan.DefaultConfig().ExcludedPaths {
		if strings.ContainsAny(value, "*.") {
			// Dot-prefixed directory names are meaningful; file-like patterns
			// such as go.sum/package-lock.json are not directory exclusions.
			if strings.Contains(value, ".") && !strings.HasPrefix(value, ".") {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func matchesAnyManifestPattern(name string) bool {
	for _, pattern := range manifestAndLockfilePatterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// RepoLevelExcludes returns the relative paths (relative to repoRoot) of
// every discovered project directory. When used as reposcan.Config.ExcludedDirs
// with Root = repoRoot, the repo-level SAST/Secrets scan walks the entire
// repo tree but skips into project directories — those are already scanned
// separately via per-project ScanRoots, so this avoids double-counting
// while still catching repo-level content (CI configs, Dockerfiles, scripts,
// shared configs, docs) that doesn't belong to any specific project.
func RepoLevelExcludes(repoRoot string, allProjects []*Project) []string {
	var dirs []string
	seen := make(map[string]bool)
	for _, p := range allProjects {
		absDir := filepath.Clean(p.Dir)
		rel, err := filepath.Rel(repoRoot, absDir)
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if !seen[rel] {
			seen[rel] = true
			dirs = append(dirs, rel)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// RepoLevelExcludesForScanUnits computes residual exclusions from the actual
// scheduled physical roots, not from every discovered project. Unselected
// projects therefore remain visible to inventory and are never accidentally
// removed from a repository-global scan.
func RepoLevelExcludesForScanUnits(repoRoot string, roots []string) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, root := range roots {
		rel, err := filepath.Rel(repoRoot, filepath.Clean(root))
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		if !seen[rel] {
			seen[rel] = true
			dirs = append(dirs, rel)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// dropNestedRoots removes any path that is a subdirectory of another path
// already in the list, so a scanner given the parent directory is never
// handed the same child directory a second time as a separate root.
func dropNestedRoots(dirs []string) []string {
	var result []string
	for _, candidate := range dirs {
		nested := false
		for _, other := range dirs {
			if candidate == other {
				continue
			}
			if strings.HasPrefix(candidate, other+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			result = append(result, candidate)
		}
	}
	return result
}
