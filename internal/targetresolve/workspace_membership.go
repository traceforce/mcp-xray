package targetresolve

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// workspaceMembership decides whether a workspace lockfile above a project
// pins it: only when the project is a member of that lockfile's workspace,
// as its package manager declares it. A lockfile above a project that is no
// member -- a root package-lock.json for the repository's own tooling over
// an independent package -- says nothing about that project's dependencies.
// Manifests are read once per directory.
type workspaceMembership struct {
	repoRoot string
	globs    map[string][]string // directory -> its npm/yarn/bun or pnpm member globs
	uv       map[string]*uvWorkspace
	cargo    map[string]*cargoWorkspace
}

func newWorkspaceMembership(repoRoot string) *workspaceMembership {
	return &workspaceMembership{repoRoot: repoRoot, globs: make(map[string][]string), uv: make(map[string]*uvWorkspace), cargo: make(map[string]*cargoWorkspace)}
}

// includes reports whether the lockfile named lockfile, in dir, is the
// lockfile of a workspace project is a member of. A plain requirements.txt
// above a manifest-less script has no workspace: it is how that script's
// dependencies are installed (rootLockfileCanPin).
func (m *workspaceMembership) includes(dir, lockfile string, project *Project) bool {
	switch lockfile {
	case "requirements.txt":
		return true
	case "uv.lock":
		workspace := findUvWorkspace(m.repoRoot, project.Dir, m.uv)
		return workspace != nil && workspace.dir == dir
	case "Cargo.lock":
		// Cargo makes every crate below a workspace root a member, unless
		// excluded, and refuses to build one that is not: the crate's
		// workspace is the lockfile's when it is the nearest one above it.
		doc, err := readCargoToml(project.ManifestPath)
		if err != nil {
			return false
		}
		workspace := findCargoWorkspace(m.repoRoot, project.Dir, doc, m.cargo)
		return workspace != nil && workspace.dir == dir
	}
	rel, err := filepath.Rel(dir, project.Dir)
	if err != nil {
		return false
	}
	return matchesWorkspaceGlobs(m.memberGlobs(dir, lockfile), filepath.ToSlash(rel))
}

// memberGlobs returns the member globs the workspace in dir declares for
// the package manager that writes lockfile: pnpm-workspace.yaml's packages
// for pnpm, package.json's workspaces (a list, or yarn's {"packages": [...]})
// for npm, yarn and bun.
func (m *workspaceMembership) memberGlobs(dir, lockfile string) []string {
	key := dir + "\x00" + lockfile
	if globs, seen := m.globs[key]; seen {
		return globs
	}
	var globs []string
	if lockfile == "pnpm-lock.yaml" {
		if data, err := readFileCapped(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil && len(data) <= maxTOMLFileSize {
			var manifest struct {
				Packages []string `yaml:"packages"`
			}
			if yaml.Unmarshal(data, &manifest) == nil {
				globs = manifest.Packages
			}
		}
	} else {
		var manifest struct {
			Workspaces json.RawMessage `json:"workspaces"`
		}
		if readJSONFile(filepath.Join(dir, "package.json"), &manifest) == nil {
			if json.Unmarshal(manifest.Workspaces, &globs) != nil {
				var yarn struct {
					Packages []string `json:"packages"`
				}
				if json.Unmarshal(manifest.Workspaces, &yarn) == nil {
					globs = yarn.Packages
				}
			}
		}
	}
	m.globs[key] = globs
	return globs
}

// matchesWorkspaceGlobs reports whether rel, a project directory relative to
// the workspace root in POSIX form, matches one of globs and none of the
// exclusions among them (pnpm's "!pattern").
func matchesWorkspaceGlobs(globs []string, rel string) bool {
	matched := false
	for _, glob := range globs {
		if exclusion, ok := strings.CutPrefix(glob, "!"); ok {
			if matchWorkspaceGlob(exclusion, rel) {
				return false
			}
		} else if matchWorkspaceGlob(glob, rel) {
			matched = true
		}
	}
	return matched
}

// matchWorkspaceGlob matches rel against one member glob: path.Match for
// each segment, and ** for any number of segments, as npm, yarn and pnpm
// read them. The memo keeps a pattern of many **s linear in its length
// times rel's, however the repository writes it.
func matchWorkspaceGlob(glob, rel string) bool {
	pattern := strings.Split(path.Clean(strings.TrimPrefix(glob, "./")), "/")
	name := strings.Split(rel, "/")
	memo := make(map[[2]int]bool)
	var match func(p, n int) bool
	match = func(p, n int) bool {
		key := [2]int{p, n}
		if result, seen := memo[key]; seen {
			return result
		}
		var result bool
		switch {
		case p == len(pattern):
			result = n == len(name)
		case pattern[p] == "**":
			result = match(p+1, n) || (n < len(name) && match(p, n+1))
		case n < len(name):
			ok, _ := path.Match(pattern[p], name[n])
			result = ok && match(p+1, n+1)
		}
		memo[key] = result
		return result
	}
	return match(0, 0)
}
