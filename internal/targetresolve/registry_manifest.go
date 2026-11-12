package targetresolve

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"mcpxray/internal/aggregation"
)

// registryManifestHit is one directory confirmed, via a valid server.json,
// to be an MCP server, independent of what implementation language it is.
type registryManifestHit struct {
	Dir  string
	Name string
	// NameConfirmed is true when Name came from the manifest's own "name"
	// field (a real, publishable registry identifier), false when Name is
	// the directory-basename fallback (registryManifestDisplayName), used
	// when the checked-in manifest still has an unsubstituted build-time
	// token. This distinction matters when a Project already exists at this
	// directory from a recognized ecosystem manifest (e.g. a Go module's
	// name derived from its module path): an unconfirmed fallback name
	// should not clobber a name that ecosystem-specific parsing already
	// derived meaningfully, but a real registry name should win.
	NameConfirmed bool

	// HasLocalPackages is true when the manifest's "packages" array is
	// non-empty -- i.e. there is at least one locally-buildable package
	// description, as opposed to only "remotes" (hosted elsewhere). See
	// describe for what a remotes-only manifest means.
	HasLocalPackages bool

	// Packages are the npm and PyPI packages the manifest says the server
	// is published as.
	Packages []registryPackage
}

// registryPackage is one package a registry manifest names.
type registryPackage struct {
	RegistryType string
	Identifier   string
}

// publishedBy reports whether project p is the source of pkg: a Node
// package of that name, or a Python project of that (normalized) name.
func (pkg registryPackage) publishedBy(p *Project) bool {
	switch pkg.RegistryType {
	case "npm":
		return p.Ecosystem == "node" && p.PackageName == pkg.Identifier
	case "pypi":
		return p.Ecosystem == "python" && p.PackageName != "" && normalizePEP503(p.PackageName) == normalizePEP503(pkg.Identifier)
	}
	return false
}

// names reports whether p publishes a package the manifest names.
func (hit registryManifestHit) names(p *Project) bool {
	for _, pkg := range hit.Packages {
		if pkg.publishedBy(p) {
			return true
		}
	}
	return false
}

// publishingProject returns the one non-test project at or below the
// manifest's directory that publishes a package the manifest names, or nil
// when none or several do. A server.json at a monorepo's root typically
// names the one workspace package that is the server.
func (hit registryManifestHit) publishingProject(projects []*Project) *Project {
	var found *Project
	for _, p := range projects {
		if !within(p.Dir, hit.Dir) || isTestShapedProject(p) || !hit.names(p) {
			continue
		}
		if found != nil && found != p {
			return nil
		}
		found = p
	}
	return found
}

// subject returns the project the manifest describes, in order of
// preference: the one project that publishes a package it names; the
// server, or else the only project, in its own directory (several can share
// it, a package.json beside a pyproject.toml); its one non-test descendant
// (server.json may sit directories above the manifest it describes, as in
// servers/Foo/server.json for servers/Foo/src/Foo.csproj).
//
// ok is false when the manifest cannot be tied to one project: its own
// directory holds several and not exactly one server, or, with no server
// there, its packages are built from code below it that holds several
// independent servers -- a root server.json naming a container image in a
// repository of servers describes one of them, but nothing says which, so
// it neither confirms nor owns any. (A remotes-only manifest describes a
// hosted server, not code below it.) A nil project with ok true means there
// is no project at or below the manifest at all: its server is in a
// language without a manifest parser.
func (hit registryManifestHit) subject(projects []*Project) (*Project, bool) {
	if named := hit.publishingProject(projects); named != nil {
		return named, true
	}
	var own, ownServers, descendants []*Project
	serverDirs := make(map[string]bool)
	for _, p := range projects {
		dir := filepath.Clean(p.Dir)
		if !within(dir, hit.Dir) || isTestShapedProject(p) {
			continue
		}
		if dir == hit.Dir {
			own = append(own, p)
			if p.Role == RoleMCPServer {
				ownServers = append(ownServers, p)
			}
			continue
		}
		descendants = append(descendants, p)
		if p.Role == RoleMCPServer {
			serverDirs[dir] = true
		}
	}
	switch {
	case len(ownServers) == 1:
		return ownServers[0], true
	case len(ownServers) > 1, len(own) > 1, hit.HasLocalPackages && len(serverDirs) > 1:
		return nil, false
	case len(own) == 1:
		return own[0], true
	case len(descendants) == 1:
		return descendants[0], true
	}
	return nil, true
}

// isOwnershipBoundary reports whether a server.json in dir makes dir the
// ownership root of the projects below it: dir must hold a valid registry
// manifest of a locally built server (it has packages) that can be tied to
// its subject, and that subject must not be a project publishing a package
// it names from another directory, since such a manifest describes that one
// project rather than everything below it.
func isOwnershipBoundary(repoRoot, dir string, projects []*Project) bool {
	hit, ok := readRegistryManifest(repoRoot, filepath.Join(dir, "server.json"))
	if !ok || !hit.HasLocalPackages {
		return false
	}
	described, ok := hit.subject(projects)
	return ok && (described == nil || filepath.Clean(described.Dir) == hit.Dir || !hit.names(described))
}

// isValidRegistryManifest applies a minimal structural check for the
// official MCP Registry server manifest schema
// (https://static.modelcontextprotocol.io/schemas/.../server.schema.json):
// a non-empty "name" plus a non-empty "packages" or "remotes" array. This
// guards against an unrelated file that merely happens to be named
// server.json -- a real MCP registry manifest always describes at least one
// way to obtain or reach the server.
func isValidRegistryManifest(doc map[string]interface{}) bool {
	name, hasName := doc["name"].(string)
	if !hasName || strings.TrimSpace(name) == "" {
		return false
	}
	if arr, ok := doc["packages"].([]interface{}); ok && len(arr) > 0 {
		return true
	}
	if arr, ok := doc["remotes"].([]interface{}); ok && len(arr) > 0 {
		return true
	}
	return false
}

// registryManifestDisplayName returns the manifest's own "name" field and
// true, or falls back to the containing directory's basename and false when
// the name is empty or looks like an unsubstituted build-time template
// token (e.g. "<<McpRepositoryName>>", seen verbatim in real, unbuilt
// checkouts that use MSBuild property substitution at publish time).
func registryManifestDisplayName(doc map[string]interface{}, dir string) (string, bool) {
	if name, ok := doc["name"].(string); ok {
		trimmed := strings.TrimSpace(name)
		if trimmed != "" && !strings.HasPrefix(trimmed, "<<") {
			return trimmed, true
		}
	}
	return filepath.Base(dir), false
}

// discoverRegistryManifests returns every valid server.json under repoRoot.
func discoverRegistryManifests(repoRoot string) ([]registryManifestHit, error) {
	var hits []registryManifestHit
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		if strings.ToLower(info.Name()) != "server.json" {
			return nil
		}
		if hit, ok := readRegistryManifest(repoRoot, path); ok {
			hits = append(hits, hit)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// readRegistryManifest parses the server.json at path, reporting false when
// it is not a valid MCP registry manifest -- a file merely named server.json
// is not one (isValidRegistryManifest) -- or when it is a sample
// (isSampleManifestPath).
func readRegistryManifest(repoRoot, path string) (registryManifestHit, bool) {
	if isSampleManifestPath(repoRelative(repoRoot, path)) {
		return registryManifestHit{}, false
	}
	dir := filepath.Dir(path)
	var doc map[string]interface{}
	if err := readJSONFile(path, &doc); err != nil || !isValidRegistryManifest(doc) {
		return registryManifestHit{}, false
	}
	name, confirmed := registryManifestDisplayName(doc, dir)
	hit := registryManifestHit{Dir: filepath.Clean(dir), Name: name, NameConfirmed: confirmed}
	packages, _ := doc["packages"].([]interface{})
	hit.HasLocalPackages = len(packages) > 0
	for _, value := range packages {
		pkg, _ := value.(map[string]interface{})
		registryType, _ := pkg["registryType"].(string)
		identifier, _ := pkg["identifier"].(string)
		if identifier = strings.TrimSpace(identifier); identifier != "" && !strings.HasPrefix(identifier, "<<") {
			hit.Packages = append(hit.Packages, registryPackage{RegistryType: registryType, Identifier: identifier})
		}
	}
	return hit, true
}

// applyRegistryManifestSignals applies the authoritative, language-agnostic
// signal: a directory with a valid server.json describes an MCP server,
// whatever the source heuristics in signals.go concluded. The manifest
// describes its subject; with no project at or below it at all, a minimal
// Project is synthesized, so a server in a language without a manifest
// parser is still found. Ambiguity never upgrades a project: a server's own
// test project must never take its server.json, and a manifest that cannot
// say which of several projects it describes is left out.
func applyRegistryManifestSignals(repoRoot string, projects []*Project) ([]*Project, error) {
	hits, err := discoverRegistryManifests(repoRoot)
	if err != nil {
		return projects, err
	}

	for _, hit := range hits {
		described, ok := hit.subject(projects)
		if !ok {
			continue
		}
		switch {
		case described == nil:
			synthesized := &Project{
				Name:      hit.Name,
				Dir:       hit.Dir,
				RelDir:    repoRelative(repoRoot, hit.Dir),
				Ecosystem: "unknown",
			}
			hit.describe(synthesized, "; no recognized ecosystem manifest found in this directory")
			projects = append(projects, synthesized)
		case filepath.Clean(described.Dir) == hit.Dir:
			hit.describe(described, "")
		case hit.names(described):
			hit.describe(described, fmt.Sprintf(" (server.json at %s names this package)", repoRelative(repoRoot, hit.Dir)))
		default:
			hit.describe(described, " (server.json found in an ancestor directory)")
		}
	}

	return projects, nil
}

// describe applies the manifest to the project it describes. A manifest
// with a package confirms the project as a server. A remotes-only manifest
// makes the project a remote reference, unless its own source already shows
// it is a server: a local proxy or development build of a hosted server is
// still code to scan.
func (hit registryManifestHit) describe(p *Project, note string) {
	switch {
	case hit.HasLocalPackages:
		p.Role, p.RoleConfirmedByManifest = RoleMCPServer, true
		p.Evidence = append(p.Evidence, "confirmed as an MCP server by a server.json registry manifest"+note)
	case p.Role == RoleMCPServer:
		p.Evidence = append(p.Evidence, `server.json declares only remote endpoints ("remotes"); kept as a server for its own server code`+note)
	default:
		p.Role, p.RoleConfirmedByManifest = RoleRemoteReference, false
		p.Evidence = append(p.Evidence, `server.json declares only remote endpoints ("remotes"), no locally-buildable package -- classified as a remote reference rather than a local scan target`+note)
	}
	if hit.NameConfirmed {
		p.Name = hit.Name
	}
}

// isSampleManifestPath reports whether the server.json at the
// repository-relative relPath is a sample rather than the description of a
// server in this repository: it sits among tests, fixtures, documentation or
// examples (aggregation.ContextForPath), or in a test-shaped directory, the
// rule that keeps a project there from ever being a server
// (isTestShapedProject).
func isSampleManifestPath(relPath string) bool {
	switch aggregation.ContextForPath(relPath) {
	case "test", "fixture", "docs", "example":
		return true
	}
	return isTestShapedDir(path.Dir(relPath))
}
