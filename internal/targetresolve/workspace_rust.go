package targetresolve

import "path/filepath"

// readCargoToml centralizes the read+parse boilerplate, mirroring
// readPyprojectToml. Parsed into an untyped map because Cargo.toml's
// [dependencies] values can be a bare version string OR an inline table
// ({ path = "..." }, { workspace = true }, { git = "...", branch = "..." },
// { version = "...", features = [...] }) -- the same dynamic-navigation
// style workspace_python.go already uses for pyproject.toml, for the same
// reason.
func readCargoToml(manifestPath string) (map[string]interface{}, error) {
	var doc map[string]interface{}
	if err := readTOMLFile(manifestPath, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// newRustProject builds a Project from a discovered Cargo.toml file. A
// Cargo.toml with no [package] table at all is a "virtual manifest" --
// purely a workspace root declaring [workspace] members, not itself a
// crate -- and returns (nil, nil), the same "not a project" signal every
// constructor may return, already tolerated by discoverProjects (see
// discover.go's `if project != nil` check).
func newRustProject(manifestPath string) (*Project, error) {
	doc, err := readCargoToml(manifestPath)
	if err != nil {
		return nil, err
	}

	pkgName, hasPackage := stringAt(doc, "package", "name")
	if !hasPackage {
		return nil, nil
	}

	dir := filepath.Dir(manifestPath)
	name := pkgName
	if name == "" {
		name = filepath.Base(dir)
	}

	return &Project{
		Name:         name,
		Dir:          dir,
		Ecosystem:    "rust",
		ManifestPath: manifestPath,
	}, nil
}

// cargoHasDependency reports whether any of doc's dependency tables
// ([dependencies], [dev-dependencies], [build-dependencies]) depends on the
// crate named crateName, regardless of whether its value is a bare version
// string, a { path = ... } table, or a { workspace = true } table -- the
// dependency's mere presence is what signals SDK usage, not how its version
// is resolved. A renamed dependency counts under its real package name, not
// its local key -- whether the rename is inline (mcp = { package = "rmcp" })
// or inherited from workspace's [workspace.dependencies] (mcp.workspace =
// true). workspace may be nil when the crate has none.
func cargoHasDependency(doc map[string]interface{}, crateName string, workspace *cargoWorkspace) bool {
	for _, deps := range cargoDependencyTables(doc) {
		for depName, depValue := range deps {
			if resolveCargoDep(depName, depValue, "", workspace).packageName == crateName {
				return true
			}
		}
	}
	return false
}

// resolveRustLocalDeps fills in LocalDeps for every discovered Rust project
// by inspecting [dependencies]/[dev-dependencies]/[build-dependencies]
// entries for two ways a Cargo.toml expresses "use my workspace sibling,
// not crates.io":
//
//   - a "path" key (e.g. { path = "../shared" }) -- resolved directly
//     against discovered projects' directories, the same way Node's
//     file:/link: protocols and Python's Poetry path dependencies already
//     are.
//   - anything else (a bare version string, { workspace = true }, or a
//     table with "version"/"features" but no "path") -- resolved by
//     matching the dependency's real package name against another
//     discovered Rust project's own declared package name, the same
//     accepted-tradeoff fallback already used for Go and Node
//     (workspace_node.go's plain-version-key broadening). Confirmed
//     necessary by BrowserOS's real browseros-mcp crate, consumed via
//     `browseros-mcp.workspace = true` (no path, no bare version) by its
//     sibling claw-server-rust binary.
//
// The real package name is the "package" key when the dependency is renamed
// (local = { package = "shared-lib", ... }), and only otherwise the TOML key,
// which is merely the name the crate is imported under. A
// { workspace = true } entry inherits its definition -- package, path or git
// -- from the workspace root's [workspace.dependencies] table, where such
// renames and paths normally live (see resolveCargoDep).
//
// A "git" dependency is never treated as local via the name-match fallback,
// regardless of what it is named -- it explicitly points at an external
// repository.
func resolveRustLocalDeps(repoRoot string, projects []*Project) {
	byName := make(map[string]*Project)
	byDir := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem != "rust" {
			continue
		}
		byName[p.Name] = p
		byDir[filepath.Clean(p.Dir)] = p
	}
	if len(byDir) == 0 {
		return
	}

	workspaces := make(map[string]*cargoWorkspace)
	for _, p := range projects {
		if p.Ecosystem != "rust" {
			continue
		}
		doc, err := readCargoToml(p.ManifestPath)
		if err != nil {
			continue
		}
		workspace := findCargoWorkspace(repoRoot, p.Dir, doc, workspaces)

		for _, depTable := range cargoDependencyTables(doc) {
			for depName, depValue := range depTable {
				dep := resolveCargoDep(depName, depValue, p.Dir, workspace)
				switch {
				case dep.dir != "":
					if target, ok := byDir[dep.dir]; ok && target != p {
						addLocalDep(p, target.Dir)
					}
				case dep.external:
					// A git dependency names an external repository; a
					// local crate sharing its name is not what it builds.
				default:
					if target, ok := byName[dep.packageName]; ok && target != p {
						addLocalDep(p, target.Dir)
					}
				}
			}
		}
	}
}

// cargoDepTarget is what one Cargo dependency entry points at.
type cargoDepTarget struct {
	packageName string // the crate's real package name
	dir         string // cleaned absolute directory of a path dependency, else ""
	external    bool   // a git dependency: never a workspace-local edge
}

// resolveCargoDep interprets one dependency entry declared in the manifest in
// manifestDir. When the entry is { workspace = true } and workspace defines
// depName, the workspace's definition is used instead, with its path resolved
// against the workspace root (Cargo's own inheritance rule); otherwise the
// entry's own "package"/"path"/"git" keys apply. workspace may be nil.
func resolveCargoDep(depName string, value interface{}, manifestDir string, workspace *cargoWorkspace) cargoDepTarget {
	table, ok := value.(map[string]interface{})
	if !ok {
		return cargoDepTarget{packageName: depName}
	}
	if inherited, _ := table["workspace"].(bool); inherited && workspace != nil {
		if definition, ok := workspace.dependencies[depName]; ok {
			return resolveCargoDep(depName, definition, workspace.dir, nil)
		}
	}
	dep := cargoDepTarget{packageName: depName}
	if name, ok := table["package"].(string); ok && name != "" {
		dep.packageName = name
	}
	if path, ok := table["path"].(string); ok {
		dep.dir = filepath.Clean(filepath.Join(manifestDir, filepath.FromSlash(path)))
	} else if _, hasGit := table["git"]; hasGit {
		dep.external = true
	}
	return dep
}

// cargoWorkspace is a Cargo workspace root: its directory and its
// [workspace.dependencies] table.
type cargoWorkspace struct {
	dir          string
	dependencies map[string]interface{}
}

// findCargoWorkspace returns the workspace the crate in crateDir belongs to,
// following Cargo's own rule: the directory named by the crate's
// package.workspace key if it sets one, otherwise the nearest Cargo.toml at or
// above crateDir that declares a [workspace] table. Nothing outside repoRoot
// is ever read (see loadCargoWorkspace). Results are memoized per directory
// in cache (a nil entry records "no workspace manifest here"). Returns nil
// when there is no workspace.
func findCargoWorkspace(repoRoot, crateDir string, crateDoc map[string]interface{}, cache map[string]*cargoWorkspace) *cargoWorkspace {
	if explicit, ok := stringAt(crateDoc, "package", "workspace"); ok && explicit != "" {
		return loadCargoWorkspace(repoRoot, filepath.Clean(filepath.Join(crateDir, filepath.FromSlash(explicit))), cache)
	}
	for dir := filepath.Clean(crateDir); within(dir, repoRoot); dir = filepath.Dir(dir) {
		if workspace := loadCargoWorkspace(repoRoot, dir, cache); workspace != nil {
			return workspace
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return nil
}

// loadCargoWorkspace returns the workspace declared by dir/Cargo.toml, or nil
// when that manifest is missing, unparseable, has no [workspace] table, or
// does not really live inside repoRoot. The containment check resolves
// symlinks on both sides, so neither a package.workspace path through a
// symlinked directory nor a symlinked Cargo.toml can make the resolver read a
// manifest outside the repository being analyzed.
func loadCargoWorkspace(repoRoot, dir string, cache map[string]*cargoWorkspace) *cargoWorkspace {
	if workspace, seen := cache[dir]; seen {
		return workspace
	}
	var workspace *cargoWorkspace
	manifest := filepath.Join(dir, "Cargo.toml")
	if withinRealPath(manifest, repoRoot) {
		if doc, err := readCargoToml(manifest); err == nil {
			if _, isWorkspace := mapAt(doc, "workspace"); isWorkspace {
				dependencies, _ := mapAt(doc, "workspace", "dependencies")
				workspace = &cargoWorkspace{dir: dir, dependencies: dependencies}
			}
		}
	}
	cache[dir] = workspace
	return workspace
}

// withinRealPath reports whether path still lies inside root once symlinks
// are resolved on both. A path that cannot be resolved (e.g. it does not
// exist) is reported as outside.
func withinRealPath(path, root string) bool {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	return within(realPath, realRoot)
}

// cargoDependencyTables returns every dependency table this package
// inspects: [dependencies], [dev-dependencies], [build-dependencies] --
// mirroring workspace_node.go's allDependencies() merging Node's four
// dependency kinds for the same purpose.
func cargoDependencyTables(doc map[string]interface{}) []map[string]interface{} {
	var tables []map[string]interface{}
	for _, key := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		if deps, ok := mapAt(doc, key); ok {
			tables = append(tables, deps)
		}
	}
	return tables
}
