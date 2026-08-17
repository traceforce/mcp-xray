package targetresolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WorkspaceProject is a normalized fact contributed by one of the adapters
// below -- purely additive metadata layered onto projects discoverProjects
// (plus discoverLegacyPythonScripts) already found independently by
// scanning for manifest files. None of these adapters re-implement
// discovery; every project is found regardless of workspace-membership
// declarations, by design (see workspace_node.go's own doc comment on this
// same point, which predates this file).
//
// HONEST SCOPE NOTE: of the adapters in this file, only Rush has a
// concretely observed real-world case in the repos examined this session
// (microsoft/rushstack) -- and even that case is already fully fixed by
// the signals.go namespace-signal redesign and workspace_node.go's local-
// dependency broadening, without this adapter's help at all. Its actual
// contribution here is name-normalization/observability, not edge
// resolution. Lerna, Nx, and Turborepo are implemented because proactive
// coverage of all major workspace systems was explicitly requested, not
// because a concrete gap was found for them -- their scope is
// intentionally the thinnest useful thing (detection + tagging), not
// speculative deep functionality (in particular, none of them attempt to
// reconstruct a tool's actual computed project graph).
type WorkspaceProject struct {
	Root            string // absolute path to the member project's own root
	PackageName     string // the tool's own declared name for this member, if it tracks one
	DiscoverySource string // "rush" | "lerna" | "pnpm-workspace" | "nx"
}

// discoverRushWorkspace parses rush.json's "projects" array
// (packageName/projectFolder pairs). Tolerates `//` line comments, common
// in real rush.json files (confirmed directly in microsoft/rushstack's own
// rush.json).
func discoverRushWorkspace(repoRoot string) ([]WorkspaceProject, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "rush.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var doc struct {
		Projects []struct {
			PackageName   string `json:"packageName"`
			ProjectFolder string `json:"projectFolder"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(stripJSONLineComments(data), &doc); err != nil {
		return nil, fmt.Errorf("parsing rush.json: %w", err)
	}

	result := make([]WorkspaceProject, 0, len(doc.Projects))
	for _, p := range doc.Projects {
		if p.ProjectFolder == "" {
			continue
		}
		result = append(result, WorkspaceProject{
			Root:            filepath.Join(repoRoot, filepath.FromSlash(p.ProjectFolder)),
			PackageName:     p.PackageName,
			DiscoverySource: "rush",
		})
	}
	return result, nil
}

// discoverLernaWorkspace parses lerna.json's "packages" glob list --
// structurally identical to npm's own already-deliberately-unparsed
// "workspaces" glob field (see workspace_node.go). Returns the raw glob
// patterns; applyGlobWorkspaceAdapter resolves them against already-
// discovered projects.
func discoverLernaWorkspace(repoRoot string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "lerna.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing lerna.json: %w", err)
	}
	return doc.Packages, nil
}

// discoverPnpmWorkspace parses pnpm-workspace.yaml's "packages" glob list
// (gopkg.in/yaml.v3, already a direct dependency in go.mod, previously
// unused by this package). pnpm intentionally has no "workspaces" field in
// package.json (unlike npm/yarn), so this is the only way to see pnpm's
// glob membership at all -- though the actual local-dependency-edge
// resolution need this would otherwise serve is already covered by
// workspace_node.go's plain-version-key broadening, the same way it covers
// twilio-labs/mcp.
func discoverPnpmWorkspace(repoRoot string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "pnpm-workspace.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Packages []string `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing pnpm-workspace.yaml: %w", err)
	}
	return doc.Packages, nil
}

// discoverTurborepoWorkspace detects turbo.json's mere presence only --
// turbo.json declares task/pipeline config, never a project list;
// Turborepo relies entirely on the underlying npm/yarn/pnpm workspace
// declaration for actual membership, already handled by the other adapters
// and by workspace_node.go's resolveNodeLocalDeps. This is the thinnest of
// the adapters here, by necessity -- there is nothing else to extract.
func discoverTurborepoWorkspace(repoRoot string) bool {
	_, err := os.Stat(filepath.Join(repoRoot, "turbo.json"))
	return err == nil
}

// discoverNxWorkspace is gated on nx.json's presence at repoRoot (a
// subdirectory nx.json is a possible future extension, not handled here).
// Modern Nx computes its actual project graph via CLI/plugin resolution,
// explicitly out of scope (no shelling out, no deep tooling). This adapter
// does the minimum useful thing: for each already-discovered project
// directory, if a sibling project.json exists with its own "name" field,
// records it as an additional name/tag signal. A missing or malformed
// project.json is silently skipped for that one project, consistent with
// how a malformed ecosystem manifest is already handled elsewhere in this
// package (e.g. registry_manifest.go's discoverRegistryManifests).
func discoverNxWorkspace(repoRoot string, projects []*Project) []WorkspaceProject {
	if _, err := os.Stat(filepath.Join(repoRoot, "nx.json")); err != nil {
		return nil
	}

	var result []WorkspaceProject
	for _, p := range projects {
		data, err := os.ReadFile(filepath.Join(p.Dir, "project.json"))
		if err != nil {
			continue
		}
		var doc struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &doc); err != nil || doc.Name == "" {
			continue
		}
		result = append(result, WorkspaceProject{Root: p.Dir, PackageName: doc.Name, DiscoverySource: "nx"})
	}
	return result
}

// stripJSONLineComments removes `//` line comments from a JSONC-ish
// document (rush.json commonly has them) so encoding/json can parse it --
// tracks string/escape state so a "//" inside a string literal (e.g. a URL
// in a comment-adjacent field) is never stripped. Deliberately minimal: no
// /* */ block comments (not seen in practice), no trailing-comma tolerance
// (a common JSON5-ism, a residual, named limitation, not solved here).
func stripJSONLineComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(data) && data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// applyWorkspaceRegistrySignals runs every adapter above, attaches
// WorkspaceSources tags to matching projects (by exact directory for Rush/
// Nx, by resolved glob match for Lerna/pnpm), applies Rush's defensive Name
// correction, and returns human-readable warnings for any adapter parse
// failure or Turborepo's detection note.
func applyWorkspaceRegistrySignals(repoRoot string, projects []*Project) []string {
	var warnings []string
	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	if rushProjects, err := discoverRushWorkspace(repoRoot); err != nil {
		warnings = append(warnings, fmt.Sprintf("rush.json: %v", err))
	} else {
		for _, wp := range rushProjects {
			p, ok := byDir[filepath.Clean(wp.Root)]
			if !ok {
				continue
			}
			p.WorkspaceSources = append(p.WorkspaceSources, "rush")
			// Defensive Name correction: only when the existing name is
			// still the directory-basename fallback -- mirrors
			// registry_manifest.go's NameConfirmed precedent, never
			// clobbers a real package.json name.
			if wp.PackageName != "" && p.Name == filepath.Base(p.Dir) {
				p.Name = wp.PackageName
			}
		}
	}

	applyGlobWorkspaceAdapter(repoRoot, projects, "lerna.json", discoverLernaWorkspace, "lerna", &warnings)
	applyGlobWorkspaceAdapter(repoRoot, projects, "pnpm-workspace.yaml", discoverPnpmWorkspace, "pnpm-workspace", &warnings)

	for _, wp := range discoverNxWorkspace(repoRoot, projects) {
		if p, ok := byDir[filepath.Clean(wp.Root)]; ok {
			p.WorkspaceSources = append(p.WorkspaceSources, "nx")
		}
	}

	if discoverTurborepoWorkspace(repoRoot) {
		warnings = append(warnings, "turbo.json detected; Turborepo project membership is resolved via the underlying npm/yarn/pnpm workspace declaration, not tracked separately")
	}

	return warnings
}

// applyGlobWorkspaceAdapter is shared by the two adapters (Lerna, pnpm)
// whose only contribution is a list of glob patterns: it resolves each
// pattern against repoRoot and tags any already-discovered project whose
// directory matches a resulting candidate.
func applyGlobWorkspaceAdapter(repoRoot string, projects []*Project, manifestName string, discover func(string) ([]string, error), source string, warnings *[]string) {
	patterns, err := discover(repoRoot)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("%s: %v", manifestName, err))
		return
	}
	if len(patterns) == 0 {
		return
	}

	candidateDirs := make(map[string]bool)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pattern)))
		if err != nil {
			continue
		}
		for _, m := range matches {
			candidateDirs[filepath.Clean(m)] = true
		}
	}
	if len(candidateDirs) == 0 {
		return
	}

	for _, p := range projects {
		if candidateDirs[filepath.Clean(p.Dir)] {
			p.WorkspaceSources = append(p.WorkspaceSources, source)
		}
	}
}
