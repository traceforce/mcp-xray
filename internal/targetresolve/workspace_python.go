package targetresolve

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// normalizePEP503 normalizes a Python package name per PEP 503:
// lowercase, and runs of [-_.] collapsed to a single hyphen.
func normalizePEP503(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
}

// readPyprojectToml centralizes the read+parse boilerplate every pass over a
// pyproject.toml needs (project construction, local-dep resolution, role
// signal detection). The document is returned as an untyped
// map[string]interface{} rather than a fixed struct because pyproject.toml
// has no single canonical shape -- Poetry, PEP 621, and uv each use
// different tables -- and the codebase already favors this dynamic-navigation
// approach for loosely-typed external data (see pentest's
// extractValueFromResponse).
func readPyprojectToml(manifestPath string) (map[string]interface{}, error) {
	var doc map[string]interface{}
	if err := readTOMLFile(manifestPath, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// newPythonProject builds a Project from a discovered pyproject.toml file.
// The project name is read from [project].name (PEP 621) if present,
// falling back to [tool.poetry].name, then the directory's base name.
func newPythonProject(manifestPath string) (*Project, error) {
	doc, err := readPyprojectToml(manifestPath)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(manifestPath)
	packageName, ok := stringAt(doc, "project", "name")
	if !ok {
		packageName, _ = stringAt(doc, "tool", "poetry", "name")
	}
	name := packageName
	if name == "" {
		name = filepath.Base(dir)
	}

	return &Project{
		Name:         name,
		PackageName:  packageName,
		Dir:          dir,
		Ecosystem:    "python",
		ManifestPath: manifestPath,
	}, nil
}

// resolvePythonLocalDeps fills in LocalDeps for every discovered Python
// project by inspecting two dependency declaration styles:
//
//   - Poetry path dependencies: [tool.poetry.dependencies] and every
//     [tool.poetry.group.<name>.dependencies], where an entry written as an
//     inline table with a "path" key (e.g. `shared = { path = "../shared" }`)
//     names a workspace-local dependency.
//   - uv workspace sources: [tool.uv.sources] entries, either
//     `{ path = "../shared" }` (resolved the same way as a Poetry path dep)
//     or `{ workspace = true }` (resolved by matching the dependency's TOML
//     key against another discovered Python project's declared name --
//     mirroring how the Node resolver treats the pnpm/yarn "workspace:"
//     protocol). As uv does, a workspace member also inherits the workspace
//     root's sources (findUvWorkspace) for the dependencies it declares and
//     does not define a source for itself: an example server in the
//     Python SDK's workspace depends on "mcp", and the root's
//     `mcp = { workspace = true }` makes that the SDK in the repository.
//
// A PEP 621 project that declares plain string dependency specifiers in
// [project.dependencies] (e.g. "shared-lib @ file:///../shared-lib") is not
// parsed for local-path references in this pass; Poetry and uv cover the
// workspace styles actually seen in the repositories this feature targets.
func resolvePythonLocalDeps(repoRoot string, projects []*Project) {
	byName := make(map[string]*Project)
	byDir := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem != "python" {
			continue
		}
		// As for Node, only a declared name can be depended on.
		if p.PackageName != "" {
			byName[normalizePEP503(p.PackageName)] = p
		}
		byDir[filepath.Clean(p.Dir)] = p
	}
	if len(byDir) == 0 {
		return
	}

	workspaces := make(map[string]*uvWorkspace)
	for _, p := range projects {
		if p.Ecosystem != "python" {
			continue
		}
		doc, err := readPyprojectToml(p.ManifestPath)
		if err != nil {
			continue
		}

		runtime := pythonRuntimeDependencies(doc)
		for _, depTable := range poetryDependencyTables(doc) {
			for depName, dep := range depTable {
				if path, ok := pathFromInlineTable(dep); ok {
					resolvePyPathDep(p, byDir, filepath.Join(p.Dir, path), !runtime[normalizePEP503(depName)])
				}
			}
		}

		sources, _ := mapAt(doc, "tool", "uv", "sources")
		ownSources := make(map[string]bool, len(sources))
		for depName, depValue := range sources {
			ownSources[normalizePEP503(depName)] = true
			resolveUvSource(p, depName, depValue, p.Dir, !runtime[normalizePEP503(depName)], byName, byDir)
		}
		if workspace := findUvWorkspace(repoRoot, p.Dir, workspaces); workspace != nil {
			declared := pythonDeclaredDependencies(doc)
			for depName, depValue := range workspace.sources {
				if name := normalizePEP503(depName); declared[name] && !ownSources[name] {
					resolveUvSource(p, depName, depValue, workspace.dir, !runtime[name], byName, byDir)
				}
			}
		}
	}
}

// resolveUvSource records the workspace-local dependency a [tool.uv.sources]
// entry defines for p: a path source, relative to baseDir (the directory of
// the pyproject.toml defining the entry), or a workspace member, named by
// the entry's key.
func resolveUvSource(p *Project, depName string, value interface{}, baseDir string, devOnly bool, byName, byDir map[string]*Project) {
	inline, ok := value.(map[string]interface{})
	if !ok {
		return
	}
	if path, ok := pathFromInlineTable(inline); ok {
		resolvePyPathDep(p, byDir, filepath.Join(baseDir, path), devOnly)
		return
	}
	if ws, _ := inline["workspace"].(bool); ws {
		if dep, ok := byName[normalizePEP503(depName)]; ok && dep != p {
			addPythonLocalDep(p, dep, devOnly)
		}
	}
}

// uvWorkspace is a uv workspace root: the directory of a pyproject.toml
// declaring [tool.uv.workspace], the member and exclude globs of that
// table, and the [tool.uv.sources] its members inherit.
type uvWorkspace struct {
	dir              string
	members, exclude []string
	sources          map[string]interface{}
}

// findUvWorkspace returns the workspace the project in dir is a member of,
// following uv's own rule: the nearest pyproject.toml at or above dir that
// declares [tool.uv.workspace] is the workspace root, and dir must match one
// of its members globs and none of its exclude globs. It returns nil when
// there is no workspace, when dir is no member, or when dir is the root
// itself, whose sources are its own. Nothing outside repoRoot is read
// (loadUvWorkspace), and results are memoized per directory in cache.
func findUvWorkspace(repoRoot, dir string, cache map[string]*uvWorkspace) *uvWorkspace {
	dir = filepath.Clean(dir)
	for cur := dir; within(cur, repoRoot); cur = filepath.Dir(cur) {
		if workspace := loadUvWorkspace(repoRoot, cur, cache); workspace != nil {
			if cur == dir || !workspace.hasMember(dir) {
				return nil
			}
			return workspace
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// loadUvWorkspace returns the workspace dir/pyproject.toml declares, or nil
// when it declares none or is missing, unparseable, or not really inside
// repoRoot (withinRealPath, as for Cargo workspaces).
func loadUvWorkspace(repoRoot, dir string, cache map[string]*uvWorkspace) *uvWorkspace {
	if workspace, seen := cache[dir]; seen {
		return workspace
	}
	var workspace *uvWorkspace
	manifest := filepath.Join(dir, "pyproject.toml")
	if withinRealPath(manifest, repoRoot) {
		if doc, err := readPyprojectToml(manifest); err == nil {
			if table, ok := mapAt(doc, "tool", "uv", "workspace"); ok {
				sources, _ := mapAt(doc, "tool", "uv", "sources")
				workspace = &uvWorkspace{dir: dir, members: stringList(table["members"]), exclude: stringList(table["exclude"]), sources: sources}
			}
		}
	}
	cache[dir] = workspace
	return workspace
}

// hasMember reports whether the project in dir is one of the workspace's
// members.
func (workspace *uvWorkspace) hasMember(dir string) bool {
	rel, err := filepath.Rel(workspace.dir, dir)
	if err != nil {
		return false
	}
	matches := func(globs []string) bool {
		for _, glob := range globs {
			if matchWorkspaceGlob(glob, filepath.ToSlash(rel)) {
				return true
			}
		}
		return false
	}
	return matches(workspace.members) && !matches(workspace.exclude)
}

func stringList(value interface{}) []string {
	items, _ := value.([]interface{})
	var list []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			list = append(list, s)
		}
	}
	return list
}

// poetryDependencyTables returns every dependency table this package knows
// how to read a "path" style local dependency out of: [tool.poetry.dependencies]
// plus every [tool.poetry.group.*.dependencies].
func poetryDependencyTables(doc map[string]interface{}) []map[string]interface{} {
	var tables []map[string]interface{}

	if deps, ok := mapAt(doc, "tool", "poetry", "dependencies"); ok {
		tables = append(tables, deps)
	}

	if groups, ok := mapAt(doc, "tool", "poetry", "group"); ok {
		for _, groupValue := range groups {
			group, ok := groupValue.(map[string]interface{})
			if !ok {
				continue
			}
			if deps, ok := group["dependencies"].(map[string]interface{}); ok {
				tables = append(tables, deps)
			}
		}
	}

	return tables
}

func resolvePyPathDep(p *Project, byDir map[string]*Project, targetDir string, devOnly bool) {
	if dep, ok := byDir[filepath.Clean(targetDir)]; ok && dep != p {
		addPythonLocalDep(p, dep, devOnly)
	}
}

// addPythonLocalDep records p's dependency on dep, marking it development
// only when p does not need it to run.
func addPythonLocalDep(p, dep *Project, devOnly bool) {
	addLocalDep(p, dep.Dir)
	if devOnly {
		if i, found := slices.BinarySearch(p.DevLocalDeps, dep.Dir); !found {
			p.DevLocalDeps = slices.Insert(p.DevLocalDeps, i, dep.Dir)
		}
	}
}

// pythonRuntimeDependencies returns the PEP 503 names of the distributions
// a project needs to run: [project].dependencies and optional-dependencies,
// and Poetry's main dependency table. A project that declares its
// dependencies dynamic lists them in a Hatch metadata hook instead
// (uv-dynamic-versioning's pins a workspace sibling to the package's own
// version: "mcp-types=={{ version }}"). Dependency groups are development
// only: they are never installed with the package.
func pythonRuntimeDependencies(doc map[string]interface{}) map[string]bool {
	runtime := make(map[string]bool)
	if deps, ok := valueAt(doc, "project", "dependencies"); ok {
		addPEP508Names(runtime, deps)
	}
	dynamic, _ := valueAt(doc, "project", "dynamic")
	if fields, _ := dynamic.([]interface{}); slices.Contains(fields, interface{}("dependencies")) {
		if hooks, ok := mapAt(doc, "tool", "hatch", "metadata", "hooks"); ok {
			for _, hook := range hooks {
				if hook, ok := hook.(map[string]interface{}); ok {
					addPEP508Names(runtime, hook["dependencies"])
				}
			}
		}
	}
	if extras, ok := mapAt(doc, "project", "optional-dependencies"); ok {
		for _, deps := range extras {
			addPEP508Names(runtime, deps)
		}
	}
	if deps, ok := mapAt(doc, "tool", "poetry", "dependencies"); ok {
		for name := range deps {
			runtime[normalizePEP503(name)] = true
		}
	}
	return runtime
}

// pythonDeclaredDependencies returns the PEP 503 names of every
// distribution a project declares: the runtime ones and those of its
// dependency groups ([dependency-groups] and Poetry's groups).
func pythonDeclaredDependencies(doc map[string]interface{}) map[string]bool {
	declared := pythonRuntimeDependencies(doc)
	if groups, ok := mapAt(doc, "dependency-groups"); ok {
		for _, deps := range groups {
			addPEP508Names(declared, deps)
		}
	}
	for _, deps := range poetryDependencyTables(doc) {
		for name := range deps {
			declared[normalizePEP503(name)] = true
		}
	}
	return declared
}

// addPEP508Names adds to names the PEP 503 name of every PEP 508 specifier
// string in specs, a TOML array; other entries (a dependency group's
// include-group table) are skipped.
func addPEP508Names(names map[string]bool, specs interface{}) {
	items, _ := specs.([]interface{})
	for _, item := range items {
		if spec, ok := item.(string); ok {
			names[normalizePEP503(pep508PackageName(spec))] = true
		}
	}
}

func pathFromInlineTable(v interface{}) (string, bool) {
	table, ok := v.(map[string]interface{})
	if !ok {
		return "", false
	}
	path, ok := table["path"].(string)
	return path, ok
}

// stringAt/mapAt/valueAt walk a nested map[string]interface{} document (the
// shape go-toml/v2 produces when unmarshaling into an untyped map) by key
// path, returning ok=false if any segment is missing or of the wrong type.
func stringAt(doc map[string]interface{}, keys ...string) (string, bool) {
	v, ok := valueAt(doc, keys...)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func mapAt(doc map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	v, ok := valueAt(doc, keys...)
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]interface{})
	return m, ok
}

func valueAt(doc map[string]interface{}, keys ...string) (interface{}, bool) {
	var current interface{} = doc
	for _, key := range keys {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
