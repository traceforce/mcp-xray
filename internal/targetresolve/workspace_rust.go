package targetresolve

import (
	"os"
	"path/filepath"

	toml "github.com/pelletier/go-toml/v2"
)

// readCargoToml centralizes the read+parse boilerplate, mirroring
// readPyprojectToml. Parsed into an untyped map because Cargo.toml's
// [dependencies] values can be a bare version string OR an inline table
// ({ path = "..." }, { workspace = true }, { git = "...", branch = "..." },
// { version = "...", features = [...] }) -- the same dynamic-navigation
// style workspace_python.go already uses for pyproject.toml, for the same
// reason.
func readCargoToml(manifestPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var doc map[string]interface{}
	if err := toml.Unmarshal(data, &doc); err != nil {
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
// ([dependencies], [dev-dependencies], [build-dependencies]) has an entry
// named crateName, regardless of whether its value is a bare version
// string, a { path = ... } table, or a { workspace = true } table -- the
// dependency's mere presence is what signals SDK usage, not how its
// version is resolved.
func cargoHasDependency(doc map[string]interface{}, crateName string) bool {
	for _, deps := range cargoDependencyTables(doc) {
		if _, ok := deps[crateName]; ok {
			return true
		}
	}
	return false
}

// resolveRustLocalDeps fills in LocalDeps for every discovered Rust project
// by inspecting [dependencies]/[dev-dependencies]/[build-dependencies]
// entries for two ways a Cargo.toml expresses "use my workspace sibling,
// not crates.io":
//
//   - an inline table with a "path" key (e.g. { path = "../shared" }) --
//     resolved directly against discovered projects' directories, the same
//     way Node's file:/link: protocols and Python's Poetry path
//     dependencies already are.
//   - anything else (a bare version string, { workspace = true }, or a
//     table with "version"/"features" but no "path") -- resolved by
//     matching the dependency's TOML key against another discovered Rust
//     project's own declared package name, the same accepted-tradeoff
//     fallback already used for Go and Node (workspace_node.go's
//     plain-version-key broadening). Confirmed necessary by BrowserOS's
//     real browseros-mcp crate, consumed via
//     `browseros-mcp.workspace = true` (no path, no bare version) by its
//     sibling claw-server-rust binary.
//
// An inline table with a "git" key is never treated as local via the
// name-match fallback, regardless of what its key is named -- it
// explicitly points at an external repository.
func resolveRustLocalDeps(projects []*Project) {
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

	for _, p := range projects {
		if p.Ecosystem != "rust" {
			continue
		}
		doc, err := readCargoToml(p.ManifestPath)
		if err != nil {
			continue
		}

		for _, depTable := range cargoDependencyTables(doc) {
			for depName, depValue := range depTable {
				if table, ok := depValue.(map[string]interface{}); ok {
					if path, ok := table["path"].(string); ok {
						resolveRustPathDep(p, byDir, path)
						continue
					}
					if _, hasGit := table["git"]; hasGit {
						continue
					}
				}
				if dep, ok := byName[depName]; ok && dep != p {
					addLocalDep(p, dep.Dir)
				}
			}
		}
	}
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

func resolveRustPathDep(p *Project, byDir map[string]*Project, relPath string) {
	targetDir := filepath.Clean(filepath.Join(p.Dir, relPath))
	if dep, ok := byDir[targetDir]; ok && dep != p {
		addLocalDep(p, dep.Dir)
	}
}
