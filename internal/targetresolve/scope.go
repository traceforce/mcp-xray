package targetresolve

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ScanRoots returns the directories that must be scanned together for this
// target: the scan root of every included project, deduplicated, with any
// root nested inside another dropped so no file is handed to the scanners
// twice.
func (t *Target) ScanRoots() []string {
	var dirs []string
	seen := make(map[string]bool)
	for _, p := range t.Included {
		if dir := p.ScanRoot(); !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return dropNestedRoots(dirs)
}

// DependencyFiles returns, sorted, every dependency manifest and lockfile a
// scan of t alone reads under its ScanRoots: the ones in a discovered
// project (of allProjects) nested there that t does not include are left
// out, as its scan units leave that project out (nestedForeignExcludes). It
// is informational, for --list-targets: the SCA scanner finds manifests
// itself inside the directories it is given.
func (t *Target) DependencyFiles(allProjects []*Project) []string {
	included := includedScanRoots([]*Target{t})
	var found []string
	for _, root := range t.ScanRoots() {
		unit := &ScanUnit{Root: root, ExcludedDirs: nestedForeignExcludes(root, included, allProjects)} // as a plan of t alone has it
		_ = walkFiles(root, func(dir string) bool { return isExcludedFromUnit(unit, dir) }, func(path string, info os.FileInfo) error {
			if matchesAnyManifestPattern(info.Name()) {
				found = append(found, filepath.Clean(path))
			}
			return nil
		})
	}
	sort.Strings(found)
	return found
}

// residualExcludes returns the scheduled scan roots as repository-relative
// paths, for the repository-global unit to skip. Only scheduled roots are
// excluded, so unselected projects stay inside the repository-global scan.
func residualExcludes(repoRoot string, roots []string) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, root := range roots {
		if !within(root, repoRoot) || filepath.Clean(root) == filepath.Clean(repoRoot) {
			continue
		}
		if rel := repoRelative(repoRoot, root); !seen[rel] {
			seen[rel] = true
			dirs = append(dirs, rel)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// nestedForeignExcludes returns the paths, relative to unitRoot, of every
// discovered project's ownership root that is physically nested inside
// unitRoot but is not in includedRoots. Without this, a scanner recursing
// over unitRoot also walks into and reports findings for any other project
// that merely happens to live in a subdirectory -- e.g. an unrelated tool
// nested inside a selected target's own directory tree. A project that
// encloses an included root is kept, or the included project would be cut
// out too; the plan leaves its files' findings out of the report
// (ScanPlan.Reports).
//
// A foreign root nested inside another foreign root is collapsed to just the
// outer one via dropNestedRoots: Config.ShouldExclude's prefix match already
// covers the inner one, so listing both would be redundant.
func nestedForeignExcludes(unitRoot string, includedRoots map[string]bool, allProjects []*Project) []string {
	cleanUnitRoot := filepath.Clean(unitRoot)
	var foreign []string
	seen := make(map[string]bool)
	for _, p := range allProjects {
		root := p.ScanRoot()
		if p.EmbeddedScript || root == cleanUnitRoot || includedRoots[root] || !within(root, cleanUnitRoot) || enclosesAny(root, includedRoots) {
			continue // an embedded script's directory is the enclosing project's too
		}
		if !seen[root] {
			seen[root] = true
			foreign = append(foreign, root)
		}
	}
	foreign = dropNestedRoots(foreign)

	rels := make([]string, 0, len(foreign))
	for _, abs := range foreign {
		rels = append(rels, repoRelative(cleanUnitRoot, abs))
	}
	sort.Strings(rels)
	return rels
}

// enclosesAny reports whether one of roots lies below dir: excluding dir
// would cut that included project out of the scan too.
func enclosesAny(dir string, roots map[string]bool) bool {
	for root := range roots {
		if root != dir && within(root, dir) {
			return true
		}
	}
	return false
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
