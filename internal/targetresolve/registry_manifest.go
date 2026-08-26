package targetresolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan"
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
	// description, as opposed to only "remotes" (hosted elsewhere, nothing
	// local to scan). A hit with HasLocalPackages == false resolves to
	// RoleRemoteReference instead of RoleMCPServer (see
	// applyRegistryManifestSignals).
	HasLocalPackages bool
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

// discoverRegistryManifests walks repoRoot looking for valid server.json
// files, reusing reposcan's default exclude list for pruning exactly like
// discoverProjects does.
func discoverRegistryManifests(repoRoot string) ([]registryManifestHit, error) {
	prune := &reposcan.Config{
		Root:          repoRoot,
		ExcludedPaths: reposcan.DefaultConfig().ExcludedPaths,
	}

	var hits []registryManifestHit
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if prune.ShouldExclude(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() || strings.ToLower(info.Name()) != "server.json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil || !isValidRegistryManifest(doc) {
			return nil
		}

		dir := filepath.Dir(path)
		name, confirmed := registryManifestDisplayName(doc, dir)
		hasLocalPackages := false
		if arr, ok := doc["packages"].([]interface{}); ok && len(arr) > 0 {
			hasLocalPackages = true
		}
		hits = append(hits, registryManifestHit{
			Dir:              dir,
			Name:             name,
			NameConfirmed:    confirmed,
			HasLocalPackages: hasLocalPackages,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// applyRegistryManifestSignals is the universal, language-agnostic Tier 1
// signal: a directory with a valid server.json is authoritatively an MCP
// server, regardless of implementation language and regardless of whatever
// a per-ecosystem source-code heuristic (signals.go) might otherwise have
// concluded about it. For a directory where an ecosystem manifest was
// already discovered (go.mod/package.json/pyproject.toml/.csproj), this
// overrides that Project's Role. For a directory with no recognized
// ecosystem manifest at all (e.g. a language this package has no parser
// for), it synthesizes a minimal Project so the server is still found.
func applyRegistryManifestSignals(repoRoot string, projects []*Project) ([]*Project, error) {
	hits, err := discoverRegistryManifests(repoRoot)
	if err != nil {
		return projects, err
	}
	if len(hits) == 0 {
		return projects, nil
	}

	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	const evidenceConfirmed = "confirmed as an MCP server by a server.json registry manifest"
	const evidenceRemoteOnly = `server.json declares only remote endpoints ("remotes"), no locally-buildable package -- classified as a remote reference rather than a local scan target`

	for _, hit := range hits {
		dir := filepath.Clean(hit.Dir)
		role := RoleMCPServer
		evidence := evidenceConfirmed
		roleConfirmed := true
		if !hit.HasLocalPackages {
			role = RoleRemoteReference
			evidence = evidenceRemoteOnly
			roleConfirmed = false
		}

		if existing, ok := byDir[dir]; ok {
			existing.Role = role
			existing.RoleConfirmedByManifest = roleConfirmed
			if hit.NameConfirmed {
				existing.Name = hit.Name
			}
			existing.Evidence = append(existing.Evidence, evidence)
			continue
		}

		// No project exists at the exact hit directory. Before
		// synthesizing a new one, search for an existing project whose
		// directory is a DESCENDANT of hit.Dir -- a real repo shape
		// (confirmed in microsoft/mcp) has server.json sitting one or more
		// directories ABOVE the actual manifest (e.g.
		// servers/Foo.Mcp.Server/server.json vs. the real .csproj at
		// servers/Foo.Mcp.Server/src/Foo.Mcp.Server.csproj). Upgrading the
		// real, already-discovered nested project instead of synthesizing
		// a duplicate handles any nesting depth generically. Test-shaped
		// descendants (isTestShapedProject) are excluded as candidates --
		// a server.json describing a server must never be attributed to
		// that server's own test project. When the search finds zero or
		// more than one non-test-shaped candidate, fall back to today's
		// synthesize behavior (an ambiguous match is not a safe upgrade).
		if candidate := findUnambiguousDescendantProject(dir, projects); candidate != nil {
			candidate.Role = role
			candidate.RoleConfirmedByManifest = roleConfirmed
			if hit.NameConfirmed {
				candidate.Name = hit.Name
			}
			candidate.Evidence = append(candidate.Evidence, evidence+" (server.json found in an ancestor directory)")
			continue
		}

		synthesized := &Project{
			Name:                    hit.Name,
			Dir:                     hit.Dir,
			Ecosystem:               "unknown",
			Role:                    role,
			RoleConfirmedByManifest: roleConfirmed,
			Evidence:                []string{evidence + "; no recognized ecosystem manifest found in this directory"},
		}
		projects = append(projects, synthesized)
		byDir[dir] = synthesized
	}

	return projects, nil
}

// findUnambiguousDescendantProject returns the single existing project
// whose directory is a strict descendant of hitDir, excluding test-shaped
// projects (isTestShapedProject, signals.go) as candidates. Returns nil if
// there are zero or more than one such candidate -- an ambiguous match is
// not a safe upgrade, and the caller falls back to synthesizing instead.
func findUnambiguousDescendantProject(hitDir string, projects []*Project) *Project {
	var candidate *Project
	for _, p := range projects {
		pDir := filepath.Clean(p.Dir)
		if pDir == hitDir || !strings.HasPrefix(pDir, hitDir+string(filepath.Separator)) {
			continue
		}
		if isTestShapedProject(p) {
			continue
		}
		if candidate != nil {
			return nil // ambiguous: more than one non-test-shaped descendant
		}
		candidate = p
	}
	return candidate
}
