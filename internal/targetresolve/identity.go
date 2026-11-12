package targetresolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// stableID deliberately uses repository-relative paths so the same checkout
// has the same identities regardless of its absolute location.
func stableID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + filepath.ToSlash(filepath.Clean(value))))
	return kind + "-" + hex.EncodeToString(sum[:8])
}

func repoRelative(repoRoot, path string) string {
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil || rel == "." {
		if err != nil {
			return filepath.ToSlash(filepath.Clean(path))
		}
		return "."
	}
	return filepath.ToSlash(filepath.Clean(rel))
}

// projectRepoRoot recovers the repository root p was discovered under from
// p.Dir and p.RelDir (Dir is always the root joined with RelDir), for the few
// classification steps that must not look outside the repository. ok is
// false when RelDir is unknown.
func projectRepoRoot(p *Project) (root string, ok bool) {
	if p.RelDir == "" {
		return "", false
	}
	root = filepath.Clean(p.Dir)
	if p.RelDir != "." {
		for range strings.Split(p.RelDir, "/") {
			root = filepath.Dir(root)
		}
	}
	return root, true
}

// assignIdentities attaches stable project/component/target identities and
// converts dependency edges to the stable-ID representation. It is called
// only after all discovery and registry promotion is complete.
func assignIdentities(repoRoot string, projects []*Project) []*Component {
	dirs := indexProjectDirs(projects)

	for _, p := range projects {
		identityPath := p.ManifestPath
		if identityPath == "" {
			identityPath = p.Dir
		}
		p.ID = stableID("project", repoRelative(repoRoot, identityPath)+"\x00"+p.Ecosystem)
		if p.OwnershipRoot == "" {
			p.OwnershipRoot, p.OwnershipEvidence, p.OwnershipAmbiguous = inferOwnershipRoot(repoRoot, p, projects)
		}
		p.ComponentID = stableID("component", repoRelative(repoRoot, p.OwnershipRoot))
	}

	// Edges are converted only once EVERY project has its ID: a dependency
	// later in the slice would otherwise contribute an empty ID.
	for _, p := range projects {
		p.LocalDepIDs = p.LocalDepIDs[:0]
		for _, depDir := range p.LocalDeps {
			if dep := dirs.dep(p, depDir); dep != nil {
				p.LocalDepIDs = append(p.LocalDepIDs, dep.ID)
			}
		}
		sort.Strings(p.LocalDepIDs)
	}

	componentsByID := make(map[string]*Component)
	componentDirs := make(map[string]map[string]bool)
	for _, p := range projects {
		c := componentsByID[p.ComponentID]
		if c == nil {
			c = &Component{ID: p.ComponentID, Root: filepath.Clean(p.OwnershipRoot), Ambiguous: p.OwnershipAmbiguous}
			componentsByID[p.ComponentID] = c
		}
		c.ProjectIDs = append(c.ProjectIDs, p.ID)
		if componentDirs[p.ComponentID] == nil {
			componentDirs[p.ComponentID] = make(map[string]bool)
		}
		componentDirs[p.ComponentID][filepath.Clean(p.Dir)] = true
		c.Evidence = append(c.Evidence, p.OwnershipEvidence...)
		c.Ambiguous = c.Ambiguous || p.OwnershipAmbiguous
	}

	components := make([]*Component, 0, len(componentsByID))
	for _, c := range componentsByID {
		if len(componentDirs[c.ID]) > 1 {
			c.Ambiguous = true
			for _, project := range projects {
				if project.ComponentID == c.ID {
					project.OwnershipAmbiguous = true
				}
			}
		}
		sort.Strings(c.ProjectIDs)
		c.Evidence = uniqueSorted(c.Evidence)
		components = append(components, c)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })
	return components
}

// inferOwnershipRoot is intentionally conservative: the ownership root is
// the nearest directory, the project's own included, whose server.json makes
// it a boundary (isOwnershipBoundary), and otherwise the manifest directory.
// A project whose own directory holds its server.json owns that directory,
// even inside an outer boundary.
func inferOwnershipRoot(repoRoot string, p *Project, projects []*Project) (string, []string, bool) {
	start := filepath.Clean(p.Dir)
	for dir := start; ; dir = filepath.Dir(dir) {
		if isOwnershipBoundary(repoRoot, dir, projects) {
			return dir, []string{fmt.Sprintf("ownership boundary discovered at %s", repoRelative(repoRoot, dir))}, false
		}
		if dir == filepath.Clean(repoRoot) || dir == filepath.Dir(dir) {
			break
		}
	}
	return start, []string{"conservative manifest/project directory boundary"}, false
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

// ResolutionJSON is the structured target/scope listing used by automation.
// Path-bearing fields are repository-relative POSIX paths; absolute paths
// remain internal scan inputs and are not emitted in this machine-facing view.
func ResolutionJSON(r *Resolution) ([]byte, error) {
	type projectView struct {
		ID                 string   `json:"id"`
		Name               string   `json:"name"`
		Path               string   `json:"path"`
		ManifestPath       string   `json:"manifestPath,omitempty"`
		Ecosystem          string   `json:"ecosystem"`
		Role               Role     `json:"role"`
		OwnershipRoot      string   `json:"ownershipRoot"`
		OwnershipEvidence  []string `json:"ownershipEvidence,omitempty"`
		OwnershipAmbiguous bool     `json:"ownershipAmbiguous,omitempty"`
		LocalDepIDs        []string `json:"localDepIds,omitempty"`
		ComponentID        string   `json:"componentId"`
		Evidence           []string `json:"evidence,omitempty"`
	}
	type targetView struct {
		ID                 string                     `json:"id"`
		Name               string                     `json:"name"`
		ProjectID          string                     `json:"projectId"`
		ComponentID        string                     `json:"componentId"`
		IncludedProjectIDs []string                   `json:"includedProjectIds"`
		IncludedReasons    map[string]InclusionReason `json:"includedReasons,omitempty"`
	}
	type componentView struct {
		ID         string   `json:"id"`
		Root       string   `json:"root"`
		ProjectIDs []string `json:"projectIds"`
		Evidence   []string `json:"evidence,omitempty"`
		Ambiguous  bool     `json:"ambiguous,omitempty"`
	}
	view := struct {
		RepoRoot   string           `json:"repoRoot"`
		Projects   []projectView    `json:"projects"`
		Components []componentView  `json:"components"`
		Targets    []targetView     `json:"targets"`
		Inventory  []InventoryEntry `json:"inventory"`
		Excluded   []string         `json:"excluded,omitempty"`
		Warnings   []string         `json:"warnings,omitempty"`
	}{RepoRoot: ".", Projects: []projectView{}, Components: []componentView{}, Targets: []targetView{}, Inventory: r.Inventory, Excluded: r.Excluded, Warnings: r.Warnings}
	if view.Inventory == nil {
		view.Inventory = []InventoryEntry{} // a consumer iterates these lists: an empty one is [], not null
	}
	for _, p := range r.Projects {
		manifest := ""
		if p.ManifestPath != "" {
			manifest = repoRelative(r.RepoRoot, p.ManifestPath)
		}
		view.Projects = append(view.Projects, projectView{ID: p.ID, Name: p.Name, Path: repoRelative(r.RepoRoot, p.Dir), ManifestPath: manifest, Ecosystem: p.Ecosystem, Role: p.Role, OwnershipRoot: repoRelative(r.RepoRoot, p.ScanRoot()), OwnershipEvidence: p.OwnershipEvidence, OwnershipAmbiguous: p.OwnershipAmbiguous, LocalDepIDs: p.LocalDepIDs, ComponentID: p.ComponentID, Evidence: p.Evidence})
	}
	for _, c := range r.Components {
		view.Components = append(view.Components, componentView{ID: c.ID, Root: repoRelative(r.RepoRoot, c.Root), ProjectIDs: c.ProjectIDs, Evidence: c.Evidence, Ambiguous: c.Ambiguous})
	}
	for _, t := range r.Targets {
		reasons := map[string]InclusionReason{}
		for path, reason := range t.IncludedReasons {
			reasons[repoRelative(r.RepoRoot, path)] = reason
		}
		projectID := ""
		if t.Project != nil {
			projectID = t.Project.ID
		}
		view.Targets = append(view.Targets, targetView{ID: t.ID, Name: t.Name, ProjectID: projectID, ComponentID: t.ComponentID, IncludedProjectIDs: t.IncludedProjectIDs, IncludedReasons: reasons})
	}
	return json.MarshalIndent(view, "", "  ")
}
