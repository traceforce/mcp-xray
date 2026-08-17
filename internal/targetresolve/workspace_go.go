package targetresolve

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// readGoMod centralizes the read+parse boilerplate that every pass over a
// go.mod file needs (project construction, local-dep resolution, role signal
// detection), so those three passes stay small and consistent rather than
// each re-implementing the same few lines.
func readGoMod(manifestPath string) (*modfile.File, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	return modfile.Parse(manifestPath, data, nil)
}

// newGoProject builds a Project from a discovered go.mod file.
func newGoProject(manifestPath string) (*Project, error) {
	mf, err := readGoMod(manifestPath)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(manifestPath)
	name := filepath.Base(dir)
	if mf.Module != nil && mf.Module.Mod.Path != "" {
		name = lastPathSegment(mf.Module.Mod.Path)
	}

	return &Project{
		Name:         name,
		Dir:          dir,
		Ecosystem:    "go",
		ManifestPath: manifestPath,
	}, nil
}

// resolveGoLocalDeps fills in LocalDeps for every discovered Go project.
//
// Two independent signals are combined, because either one alone misses real
// cases seen in practice:
//
//  1. An explicit `replace` directive pointing at a local filesystem path --
//     the unambiguous way one module says "build against my sibling's
//     source, not a registry version".
//  2. A `require` entry whose module path matches another Go project
//     discovered elsewhere in this same repository. This is what actually
//     links modules together under a go.work-based workspace, where `use`
//     entries resolve local imports transparently and no `replace` directive
//     is present at all. go.work itself does not need to be parsed
//     separately: if a require path resolves to another module physically
//     present in this repo, that dependency is real regardless of whether a
//     go.work file mediated it.
func resolveGoLocalDeps(projects []*Project) {
	byDir := make(map[string]*Project)
	modulePathToDir := make(map[string]string)
	parsed := make(map[*Project]*modfile.File) // scoped to this call only, not a package-level cache

	for _, p := range projects {
		if p.Ecosystem != "go" {
			continue
		}
		byDir[filepath.Clean(p.Dir)] = p

		mf, err := readGoMod(p.ManifestPath)
		if err != nil {
			continue
		}
		parsed[p] = mf
		if mf.Module != nil {
			modulePathToDir[mf.Module.Mod.Path] = filepath.Clean(p.Dir)
		}
	}
	if len(byDir) == 0 {
		return
	}

	for p, mf := range parsed {
		selfDir := filepath.Clean(p.Dir)

		for _, r := range mf.Replace {
			if !isLocalFilesystemPath(r.New.Path) {
				continue
			}
			targetDir := filepath.Clean(filepath.Join(p.Dir, r.New.Path))
			if dep, ok := byDir[targetDir]; ok && dep != p {
				addLocalDep(p, dep.Dir)
			}
		}

		for _, req := range mf.Require {
			if dir, ok := modulePathToDir[req.Mod.Path]; ok && dir != selfDir {
				addLocalDep(p, dir)
			}
		}
	}
}

func isLocalFilesystemPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || filepath.IsAbs(p)
}

func lastPathSegment(modPath string) string {
	idx := strings.LastIndexByte(modPath, '/')
	if idx == -1 {
		return modPath
	}
	return modPath[idx+1:]
}

// addLocalDep appends dir to p.LocalDeps if it is not already present.
func addLocalDep(p *Project, dir string) {
	for _, existing := range p.LocalDeps {
		if existing == dir {
			return
		}
	}
	p.LocalDeps = append(p.LocalDeps, dir)
}
