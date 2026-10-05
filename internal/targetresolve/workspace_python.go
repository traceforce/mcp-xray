package targetresolve

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
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

// newPythonProject builds a Project from a discovered pyproject.toml file.
// The project name is read from [project].name (PEP 621) if present,
// falling back to [tool.poetry].name, then the directory's base name.
func newPythonProject(manifestPath string) (*Project, error) {
	doc, err := readPyprojectToml(manifestPath)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(manifestPath)
	name := filepath.Base(dir)
	if n, ok := stringAt(doc, "project", "name"); ok {
		name = n
	} else if n, ok := stringAt(doc, "tool", "poetry", "name"); ok {
		name = n
	}

	return &Project{
		Name:         name,
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
//     protocol).
//
// A PEP 621 project that declares plain string dependency specifiers in
// [project.dependencies] (e.g. "shared-lib @ file:///../shared-lib") is not
// parsed for local-path references in this pass; Poetry and uv cover the
// workspace styles actually seen in the repositories this feature targets.
func resolvePythonLocalDeps(projects []*Project) {
	byName := make(map[string]*Project)
	byDir := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem != "python" {
			continue
		}
		byName[normalizePEP503(p.Name)] = p
		byDir[filepath.Clean(p.Dir)] = p
	}
	if len(byDir) == 0 {
		return
	}

	for _, p := range projects {
		if p.Ecosystem != "python" {
			continue
		}
		doc, err := readPyprojectToml(p.ManifestPath)
		if err != nil {
			continue
		}

		for _, depTable := range poetryDependencyTables(doc) {
			for _, dep := range depTable {
				if path, ok := pathFromInlineTable(dep); ok {
					resolvePyPathDep(p, byDir, path)
				}
			}
		}

		if sources, ok := mapAt(doc, "tool", "uv", "sources"); ok {
			for depName, depValue := range sources {
				inline, ok := depValue.(map[string]interface{})
				if !ok {
					continue
				}
				if path, ok := pathFromInlineTable(inline); ok {
					resolvePyPathDep(p, byDir, path)
					continue
				}
				if ws, ok := inline["workspace"].(bool); ok && ws {
					if dep, ok := byName[normalizePEP503(depName)]; ok && dep != p {
						addLocalDep(p, dep.Dir)
					}
				}
			}
		}
	}
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

func resolvePyPathDep(p *Project, byDir map[string]*Project, relPath string) {
	targetDir := filepath.Clean(filepath.Join(p.Dir, relPath))
	if dep, ok := byDir[targetDir]; ok && dep != p {
		addLocalDep(p, dep.Dir)
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
