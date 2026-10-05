package targetresolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// nodePackageJSON is the subset of package.json fields this package cares
// about. Dependency maps are read as raw strings (not resolved semver
// ranges) because the only values that matter here are the workspace-local
// protocol prefixes ("workspace:", "file:", "link:"); registry version
// ranges are the existing SCA scanner's concern, not this package's.
type nodePackageJSON struct {
	Name                 string            `json:"name"`
	Bin                  json.RawMessage   `json:"bin"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (p *nodePackageJSON) allDependencies() map[string]string {
	merged := make(map[string]string, len(p.Dependencies)+len(p.DevDependencies)+len(p.PeerDependencies)+len(p.OptionalDependencies))
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.PeerDependencies, p.OptionalDependencies} {
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

// readPackageJSON centralizes the read+parse boilerplate every pass over a
// package.json needs (project construction, local-dep resolution, role
// signal detection).
func readPackageJSON(manifestPath string) (*nodePackageJSON, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var pkg nodePackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

// newNodeProject builds a Project from a discovered package.json file.
func newNodeProject(manifestPath string) (*Project, error) {
	pkg, err := readPackageJSON(manifestPath)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(manifestPath)
	name := pkg.Name
	if name == "" {
		name = filepath.Base(dir)
	}

	return &Project{
		Name:         name,
		Dir:          dir,
		Ecosystem:    "node",
		ManifestPath: manifestPath,
		BinNames:     parseBinNames(name, pkg.Bin),
	}, nil
}

// parseBinNames handles both of package.json's "bin" forms: a bare string
// (the binary is named after the package itself, scope-stripped -- npm's
// own convention) or an object (keys are the binary names). This is
// auxiliary identity/executability evidence only -- no execution, no
// require-following, no build-output resolution.
func parseBinNames(pkgName string, raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if asString == "" {
			return nil
		}
		return []string{binNameFromPackageName(pkgName)}
	}

	var asObject map[string]string
	if err := json.Unmarshal(raw, &asObject); err == nil && len(asObject) > 0 {
		names := make([]string, 0, len(asObject))
		for k := range asObject {
			names = append(names, k)
		}
		sort.Strings(names)
		return names
	}

	return nil
}

// binNameFromPackageName strips an npm scope ("@scope/name" -> "name") for
// the string form of "bin", where the binary is implicitly named after the
// package itself.
func binNameFromPackageName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		return name[idx+1:]
	}
	return name
}

// resolveNodeLocalDeps fills in LocalDeps for every discovered Node project
// by inspecting its package.json dependency values for the two ways a
// package manager expresses "use my workspace sibling, not the registry":
//
//   - the pnpm/yarn/npm "workspace:" protocol (e.g. "workspace:*"), where the
//     dependency KEY is the sibling package's declared "name" -- resolved by
//     matching against every other discovered Node project's Name.
//   - the "file:"/"link:" protocol, where the VALUE is a relative filesystem
//     path from this project's directory -- resolved directly against
//     discovered projects' directories.
//
// Note: package.json's own "workspaces" field and pnpm-workspace.yaml are
// deliberately not parsed for glob-based membership in this pass. Every real
// workspace-local edge this package needs to find is already expressed
// directly in a dependency's own value (one of the two protocols above, or
// the plain-version-plus-name-match fallback below), so glob-expanding the
// workspace member list would add real complexity (pattern matching, "**"
// handling pnpm supports and stdlib filepath.Glob does not) without changing
// which edges get resolved. A package.json that only declares "workspaces"
// and nothing else is simply classified RoleUnrelated by signals.go, same as
// any other project with no MCP signal -- no special-casing required.
// (workspace_registry.go's discoverPnpmWorkspace/discoverLernaWorkspace/etc.
// still parse these glob fields, but purely for naming/observability
// metadata -- not for edge resolution, which is entirely handled here.)
func resolveNodeLocalDeps(projects []*Project) {
	byName := make(map[string]*Project)
	byDir := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem != "node" {
			continue
		}
		byName[p.Name] = p
		byDir[filepath.Clean(p.Dir)] = p
	}
	if len(byDir) == 0 {
		return
	}

	for _, p := range projects {
		if p.Ecosystem != "node" {
			continue
		}
		pkg, err := readPackageJSON(p.ManifestPath)
		if err != nil {
			continue
		}

		for depName, depValue := range pkg.allDependencies() {
			switch {
			case strings.HasPrefix(depValue, "workspace:"):
				if dep, ok := byName[depName]; ok && dep != p {
					addLocalDep(p, dep.Dir)
				}
			case strings.HasPrefix(depValue, "file:"):
				resolveNodePathDep(p, byDir, strings.TrimPrefix(depValue, "file:"))
			case strings.HasPrefix(depValue, "link:"):
				resolveNodePathDep(p, byDir, strings.TrimPrefix(depValue, "link:"))
			default:
				// A plain registry-version-shaped dependency whose KEY
				// exactly matches another discovered Node project's own
				// declared name in this repo is treated as workspace-local
				// -- mirroring resolveGoLocalDeps' precedent (a `require`
				// entry matching a known local module path needs no
				// `replace` directive at all). Required for real repos like
				// twilio-labs/mcp, whose @twilio-alpha/mcp depends on its
				// sibling via "@twilio-alpha/openapi-mcp-server": "0.7.0" --
				// a plain semver string, no workspace:/file:/link: protocol
				// at all -- which would otherwise create no LocalDeps edge
				// even though the dependency is genuinely local.
				//
				// Accepted tradeoff (same one Go already accepts): an
				// unrelated local package that happens to share a name with
				// a normal registry dependency of some other project would
				// spuriously gain an edge here. Not solvable without a
				// registry lookup to disambiguate "is this really the
				// npm-published foo, or my local foo?" -- out of scope.
				if looksLikeRegistryVersionSpecifier(depValue) {
					if dep, ok := byName[depName]; ok && dep != p {
						addLocalDep(p, dep.Dir)
					}
				}
			}
		}
	}
}

// looksLikeRegistryVersionSpecifier excludes dependency values that are
// clearly not a plain local-package-name-match candidate: npm aliases
// ("npm:foo@1.0"), git/tarball URLs, "github:user/repo". None of those are
// how a workspace-local sibling is conventionally declared, and matching
// against them would risk a spurious name collision with an unrelated
// same-named local project elsewhere in a large monorepo. An empty value is
// treated as plain (some manifests leave a workspace dependency's version
// blank).
func looksLikeRegistryVersionSpecifier(v string) bool {
	if v == "" {
		return true
	}
	return !strings.ContainsAny(v, ":/")
}

func resolveNodePathDep(p *Project, byDir map[string]*Project, relPath string) {
	targetDir := filepath.Clean(filepath.Join(p.Dir, relPath))
	if dep, ok := byDir[targetDir]; ok && dep != p {
		addLocalDep(p, dep.Dir)
	}
}
