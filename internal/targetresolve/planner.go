package targetresolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	RelationDirect           = "direct"
	RelationShared           = "shared"
	RelationCompanion        = "companion"
	RelationRepositoryGlobal = "repository-global"

	// RelationWorkspaceRoot marks a finding that came from a workspace-level
	// dependency file at the repository root (e.g. a shared package-lock.json
	// backing several npm/yarn/pnpm workspace members) rather than from the
	// target's own directory. See ScanUnit.FallbackLockfiles.
	RelationWorkspaceRoot = "workspace-root-dependency"
)

// ScanUnit is one physical scanner invocation. A unit may be attributed to
// several targets, but its root/configuration is executed only once.
type ScanUnit struct {
	ID           string            `json:"id"`
	Root         string            `json:"-"`
	RelativeRoot string            `json:"root"`
	TargetIDs    []string          `json:"targetIds,omitempty"`
	Relations    map[string]string `json:"relations,omitempty"`
	ExcludedDirs []string          `json:"excludedDirs,omitempty"`
	Files        []string          `json:"files,omitempty"`
	Manifests    []string          `json:"manifests,omitempty"`
	Lockfiles    []string          `json:"lockfiles,omitempty"`

	// FallbackLockfiles is the set of repo-root-level lockfile paths (repo-
	// relative POSIX, always a file directly in the repository root) that
	// dependency scanning should additionally check on this unit's behalf,
	// because the unit's own scope -- respecting its own exclusions -- has no
	// lockfile of its own for an ecosystem it actually uses. This is the
	// shared-workspace-lockfile pattern: an npm/yarn/pnpm or Cargo workspace
	// member's own package.json/Cargo.toml declares dependencies, but only
	// the workspace root's own lockfile pins their exact resolved versions,
	// so a scan scoped to just the member's own directory has nothing to
	// resolve exact versions from. Always empty for the repository-global
	// unit itself (it already covers the repo root directly) and for any
	// unit whose own scope already has a matching lockfile.
	FallbackLockfiles []string `json:"fallbackLockfiles,omitempty"`
}

type PlanOptions struct {
	TargetIDs         []string
	AllTargets        bool
	IncludeRepoGlobal bool
	OutputPath        string
	OutputDirs        []string
}

type ScanPlan struct {
	RepoRoot           string                    `json:"-"`
	RelativeRepoRoot   string                    `json:"repoRoot"`
	SelectedTargets    []*Target                 `json:"selectedTargets"`
	Units              []*ScanUnit               `json:"scanUnits"`
	Inventory          []InventoryEntry          `json:"inventory"`
	Excluded           []string                  `json:"excluded,omitempty"`
	Unowned            []string                  `json:"unowned,omitempty"`
	Ambiguous          []string                  `json:"ambiguous,omitempty"`
	ComponentRelations map[string]string         `json:"-"`
	FileOwnership      map[string]*FileOwnership `json:"-"`
}

type TargetPlanView struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	ComponentID        string   `json:"componentId"`
	IncludedProjectIDs []string `json:"includedProjectIds"`
}
type ScanPlanView struct {
	RepoRoot        string           `json:"repoRoot"`
	SelectedTargets []TargetPlanView `json:"selectedTargets"`
	Units           []*ScanUnit      `json:"scanUnits"`
	Inventory       []InventoryEntry `json:"inventory"`
	Excluded        []string         `json:"excluded,omitempty"`
	Unowned         []string         `json:"unowned,omitempty"`
	Ambiguous       []string         `json:"ambiguous,omitempty"`
}

func StructuredScanPlan(plan *ScanPlan) ScanPlanView {
	view := ScanPlanView{RepoRoot: ".", Units: plan.Units, Inventory: plan.Inventory, Excluded: plan.Excluded, Unowned: plan.Unowned, Ambiguous: plan.Ambiguous}
	for _, target := range plan.SelectedTargets {
		view.SelectedTargets = append(view.SelectedTargets, TargetPlanView{ID: target.ID, Name: target.Name, ComponentID: target.ComponentID, IncludedProjectIDs: target.IncludedProjectIDs})
	}
	return view
}

func ScanPlanJSON(plan *ScanPlan) ([]byte, error) {
	return json.MarshalIndent(StructuredScanPlan(plan), "", "  ")
}

// BuildInventory provides one deterministic view of repository files for
// scope diagnostics. Its exclusions are intentionally separate from scanner
// exclusions: generated MCP X-Ray outputs are not inventory inputs.
func BuildInventory(repoRoot string, outputPath string, outputDirs []string) ([]InventoryEntry, []string, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, nil, err
	}
	outputFiles := generatedOutputSet(root, outputPath, outputDirs)
	var inventory []InventoryEntry
	var excluded []string
	prune := &reposcanConfigAdapter{root: root}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if prune.excludeDir(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel := repoRelative(root, path)
		if outputFiles[filepath.Clean(path)] || isGeneratedOutputPath(path) {
			excluded = append(excluded, rel)
			return nil
		}
		entry := InventoryEntry{Path: rel, Manifest: matchesManifest(filepath.Base(path)), Lockfile: matchesLockfile(filepath.Base(path))}
		entry.ProjectIDs = uniqueSorted(entry.ProjectIDs)
		entry.ComponentIDs = uniqueSorted(entry.ComponentIDs)
		if entry.Ownership == "" {
			entry.Ownership = "unowned"
		}
		inventory = append(inventory, entry)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	sort.Strings(excluded)
	return inventory, excluded, nil
}

// reposcanConfigAdapter avoids importing the scanner package into the public
// inventory model while retaining the same default directory visibility.
type reposcanConfigAdapter struct{ root string }

func (c *reposcanConfigAdapter) excludeDir(path string) bool {
	if filepath.Clean(path) == filepath.Clean(c.root) {
		return false
	}
	part := filepath.Base(path)
	for _, value := range []string{".git", ".svn", ".hg", ".bzr", "node_modules", ".venv", "venv", "vendor", "__pycache__", ".pytest_cache", ".idea", ".vscode", ".vs", ".gradle", ".mvn", ".next", ".nuxt", ".turbo", ".yarn", "coverage", ".coverage", ".nyc_output", "build", "dist", "out", "tmp", "temp", "cache"} {
		if part == value {
			return true
		}
	}
	return false
}

func generatedOutputSet(repoRoot, outputPath string, outputDirs []string) map[string]bool {
	set := make(map[string]bool)
	if outputPath != "" {
		if abs, err := filepath.Abs(outputPath); err == nil {
			set[filepath.Clean(abs)] = true
		}
	}
	for _, dir := range outputDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		filepath.Walk(abs, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				set[filepath.Clean(path)] = true
			}
			return nil
		})
	}
	return set
}

func isGeneratedOutputPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	for _, prefix := range []string{"findings-", "findings_", "merged-", "merged_", "tools_summary_", "merged_test_plan"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return strings.HasSuffix(name, ".sarif.json") && (strings.Contains(name, "mcpxray") || strings.Contains(name, "repo-scan"))
}

func matchesManifest(name string) bool {
	for _, value := range []string{"go.mod", "package.json", "pyproject.toml", "setup.py", "pom.xml", "Cargo.toml"} {
		if name == value {
			return true
		}
	}
	return strings.HasSuffix(name, ".csproj")
}
func matchesLockfile(name string) bool {
	for _, value := range []string{"go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "uv.lock", "gradle.lockfile", "Cargo.lock", "packages.lock.json"} {
		if name == value {
			return true
		}
	}
	return strings.HasSuffix(name, "requirements.txt")
}

// lockfileEcosystem returns which Project.Ecosystem value a lockfile
// basename belongs to, mirroring matchesLockfile's own list so the two never
// drift apart. Returns "" for a name matchesLockfile wouldn't recognize as a
// lockfile at all.
func lockfileEcosystem(name string) string {
	switch name {
	case "go.sum":
		return "go"
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return "node"
	case "poetry.lock", "Pipfile.lock", "uv.lock":
		return "python"
	case "gradle.lockfile":
		return "java"
	case "Cargo.lock":
		return "rust"
	case "packages.lock.json":
		return "dotnet"
	}
	if strings.HasSuffix(name, "requirements.txt") {
		return "python"
	}
	return ""
}

// BuildInventoryForResolution enriches the deterministic inventory with the
// projects/components whose ownership roots contain each file.
func BuildInventoryForResolution(repoRoot string, projects []*Project, outputPath string, outputDirs []string) ([]InventoryEntry, []string, error) {
	entries, excluded, err := BuildInventory(repoRoot, outputPath, outputDirs)
	if err != nil {
		return nil, nil, err
	}
	for i := range entries {
		abs := filepath.Join(repoRoot, filepath.FromSlash(entries[i].Path))
		for _, p := range projects {
			root := p.OwnershipRoot
			if root == "" {
				root = p.Dir
			}
			if within(abs, root) {
				entries[i].ProjectIDs = append(entries[i].ProjectIDs, p.ID)
				entries[i].ComponentIDs = append(entries[i].ComponentIDs, p.ComponentID)
				if entries[i].Ownership == "" || entries[i].Ownership == "unowned" {
					entries[i].Ownership = repoRelative(repoRoot, root)
				}
			}
		}
		entries[i].ProjectIDs = uniqueSorted(entries[i].ProjectIDs)
		entries[i].ComponentIDs = uniqueSorted(entries[i].ComponentIDs)
		if len(entries[i].ProjectIDs) == 0 {
			entries[i].Ownership = "unowned"
		}
	}
	return entries, excluded, nil
}

func within(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// BuildScanPlan creates one unit per physical ownership root and optionally
// one residual repository-global unit. Target selection is by stable ID;
// names are handled by the CLI compatibility layer before this function.
func BuildScanPlan(resolution *Resolution, options PlanOptions) (*ScanPlan, error) {
	if resolution == nil {
		return nil, fmt.Errorf("resolution is nil")
	}
	selected := make([]*Target, 0)
	requested := make(map[string]bool)
	for _, id := range options.TargetIDs {
		requested[id] = true
	}
	for _, target := range resolution.Targets {
		if options.AllTargets || requested[target.ID] {
			selected = append(selected, target)
		}
	}
	if len(options.TargetIDs) > 0 && len(selected) != len(requested) {
		return nil, fmt.Errorf("one or more target IDs were not discovered")
	}
	if len(selected) == 0 && !options.AllTargets {
		return nil, fmt.Errorf("no targets selected")
	}

	plan := &ScanPlan{RepoRoot: resolution.RepoRoot, RelativeRepoRoot: ".", SelectedTargets: selected, Inventory: resolution.Inventory}
	units := make(map[string]*ScanUnit)
	for _, target := range selected {
		for _, project := range target.Included {
			root := project.OwnershipRoot
			if root == "" {
				root = project.Dir
			}
			root = filepath.Clean(root)
			id := stableID("scan", repoRelative(resolution.RepoRoot, root))
			unit := units[id]
			if unit == nil {
				unit = &ScanUnit{ID: id, Root: root, RelativeRoot: repoRelative(resolution.RepoRoot, root), Relations: map[string]string{}}
				units[id] = unit
			}
			unit.TargetIDs = append(unit.TargetIDs, target.ID)
			relation := RelationShared
			if project == target.Project {
				relation = RelationDirect
			} else if target.IncludedReasons[filepath.Clean(project.Dir)] == InclusionTestDependent {
				relation = RelationCompanion
			}
			if current := unit.Relations[target.ID]; current == RelationDirect {
			} else {
				unit.Relations[target.ID] = relation
			}
		}
	}
	var roots []string
	for _, unit := range units {
		roots = append(roots, unit.Root)
	}
	roots = dropNestedRoots(roots)
	for id, unit := range units {
		keep := false
		for _, root := range roots {
			if unit.Root == root {
				keep = true
			}
		}
		if !keep {
			delete(units, id)
		}
	}
	if options.IncludeRepoGlobal && !containsRoot(roots, filepath.Clean(resolution.RepoRoot)) {
		id := stableID("scan", ".")
		unit := &ScanUnit{ID: id, Root: resolution.RepoRoot, RelativeRoot: ".", Relations: map[string]string{}, TargetIDs: make([]string, 0, len(selected))}
		for _, target := range selected {
			unit.TargetIDs = append(unit.TargetIDs, target.ID)
			unit.Relations[target.ID] = RelationRepositoryGlobal
		}
		unit.ExcludedDirs = RepoLevelExcludesForScanUnits(resolution.RepoRoot, roots)
		units[id] = unit
	}
	// Every ownership root any selected target actually includes, repo-wide
	// -- not just the ones the current unit itself serves. A project nested
	// inside one unit's root can legitimately belong to a DIFFERENT selected
	// target (e.g. two selected targets where one's directory sits inside
	// the other's), and dropNestedRoots above may already have folded that
	// project's own unit into this one; using the repo-wide set here means
	// nestedForeignExcludes below can never exclude something the caller
	// actually asked to scan, no matter how the units were folded together.
	allIncludedRoots := make(map[string]bool)
	for _, target := range selected {
		for _, project := range target.Included {
			root := project.OwnershipRoot
			if root == "" {
				root = project.Dir
			}
			allIncludedRoots[filepath.Clean(root)] = true
		}
	}

	for _, unit := range units {
		unit.TargetIDs = uniqueSorted(unit.TargetIDs)
		unit.ExcludedDirs = uniqueSorted(unit.ExcludedDirs)
		unit.Files, unit.Manifests, unit.Lockfiles = unitFiles(resolution.RepoRoot, unit.Root, resolution.Inventory)
		unit.ExcludedDirs = append(unit.ExcludedDirs, generatedRelativeExcludes(unit.Root, options)...)
		if filepath.Clean(unit.Root) != filepath.Clean(resolution.RepoRoot) {
			// The repository-global residual unit (Root == RepoRoot) has its
			// own, deliberately different exclusion rule immediately above
			// (RepoLevelExcludesForScanUnits): it excludes only the
			// currently-scheduled roots, so OTHER discovered-but-unselected
			// projects remain visible to a repo-global scan by design. This
			// nested-foreign check is narrower and only for a normal unit:
			// something else discovered inside THIS unit's own directory
			// tree that no selected target actually needs.
			unit.ExcludedDirs = append(unit.ExcludedDirs, nestedForeignExcludes(unit.Root, allIncludedRoots, resolution.Projects)...)
		}
		for _, excluded := range resolution.Excluded {
			abs := filepath.Join(resolution.RepoRoot, filepath.FromSlash(excluded))
			if within(abs, unit.Root) {
				rel, err := filepath.Rel(unit.Root, abs)
				if err == nil && rel != "." {
					unit.ExcludedDirs = append(unit.ExcludedDirs, filepath.ToSlash(rel))
				}
			}
		}
		unit.ExcludedDirs = uniqueSorted(unit.ExcludedDirs)
		if filepath.Clean(unit.Root) != filepath.Clean(resolution.RepoRoot) {
			unit.FallbackLockfiles = workspaceRootFallbackLockfiles(resolution, unit)
		}
		plan.Units = append(plan.Units, unit)
	}
	sort.Slice(plan.Units, func(i, j int) bool { return plan.Units[i].ID < plan.Units[j].ID })
	for _, entry := range plan.Inventory {
		if entry.Ownership == "unowned" {
			plan.Unowned = append(plan.Unowned, entry.Path)
		}
	}
	plan.Excluded = append(plan.Excluded, resolution.Excluded...)
	plan.Excluded = append(plan.Excluded, generatedRelativeExcludes(resolution.RepoRoot, options)...)
	plan.Excluded = uniqueSorted(plan.Excluded)
	for _, project := range resolution.Projects {
		if project.OwnershipAmbiguous {
			plan.Ambiguous = append(plan.Ambiguous, project.ID)
		}
	}
	sort.Strings(plan.Unowned)
	sort.Strings(plan.Ambiguous)

	plan.ComponentRelations = buildComponentRelations(selected)
	plan.FileOwnership = buildFileOwnership(resolution, plan.ComponentRelations, selected)
	applyWorkspaceRootFallbackOwnership(plan, selected)

	return plan, nil
}

// buildComponentRelations computes a deterministic relation for each
// component relative to the set of selected targets:
//   - direct:     the component is the primary component of exactly one target
//   - shared:     the component is used by more than one selected target
//   - companion:  the component is included only as a test dependent
//   - repo-global: the component is not scheduled for any target (fallback)
func buildComponentRelations(targets []*Target) map[string]string {
	usage := make(map[string]map[string]InclusionReason)
	for _, target := range targets {
		for _, project := range target.Included {
			cid := project.ComponentID
			if usage[cid] == nil {
				usage[cid] = make(map[string]InclusionReason)
			}
			reason := target.IncludedReasons[filepath.Clean(project.Dir)]
			existing := usage[cid][target.ID]
			if inclusionPriority(reason) > inclusionPriority(existing) {
				usage[cid][target.ID] = reason
			}
		}
	}

	relations := make(map[string]string, len(usage))
	for cid, targetReasons := range usage {
		if len(targetReasons) > 1 {
			relations[cid] = RelationShared
			continue
		}
		for _, reason := range targetReasons {
			if reason == InclusionPrimary {
				relations[cid] = RelationDirect
			} else if reason == InclusionTestDependent {
				relations[cid] = RelationCompanion
			} else {
				relations[cid] = RelationDirect
			}
		}
	}
	return relations
}

// buildFileOwnership creates a canonical ownership map for every file in
// the inventory. The map is keyed by repo-relative POSIX path and provides
// deterministic component, target, relation and context for each file.
func buildFileOwnership(resolution *Resolution, componentRelations map[string]string, targets []*Target) map[string]*FileOwnership {
	componentTargets := make(map[string][]string)
	for _, target := range targets {
		for _, project := range target.Included {
			cid := project.ComponentID
			componentTargets[cid] = appendUniqueStr(componentTargets[cid], target.ID)
		}
	}

	ownership := make(map[string]*FileOwnership, len(resolution.Inventory))
	for _, entry := range resolution.Inventory {
		fo := &FileOwnership{
			ComponentIDs: entry.ComponentIDs,
			Context:      aggregationContextForPath(entry.Path),
		}
		for _, cid := range entry.ComponentIDs {
			fo.TargetIDs = appendUniqueStr(fo.TargetIDs, componentTargets[cid]...)
			rel := componentRelations[cid]
			if relationPriority(rel) > relationPriority(fo.Relation) {
				fo.Relation = rel
			}
		}
		if fo.Relation == "" {
			fo.Relation = RelationRepositoryGlobal
		}
		sort.Strings(fo.TargetIDs)
		sort.Strings(fo.ComponentIDs)
		ownership[entry.Path] = fo
	}
	return ownership
}

func appendUniqueStr(s []string, values ...string) []string {
	set := make(map[string]bool, len(s)+len(values))
	for _, v := range s {
		set[v] = true
	}
	for _, v := range values {
		if v != "" && !set[v] {
			set[v] = true
			s = append(s, v)
		}
	}
	return s
}

func relationPriority(r string) int {
	switch r {
	case RelationDirect:
		return 4
	case RelationCompanion:
		return 3
	case RelationShared:
		return 2
	case RelationRepositoryGlobal:
		return 1
	default:
		return 0
	}
}

func aggregationContextForPath(path string) string {
	// Delegate to the aggregation package's canonical classification. Import
	// would create a cycle, so inline the same logic. The authoritative copy
	// lives in internal/aggregation.ContextForPath; if the two ever diverge,
	// tests will catch the mismatch because the same file must never get two
	// different contexts.
	return contextForPathLocal(path)
}

func contextForPathLocal(repoRelativePath string) string {
	path := strings.ToLower(filepath.ToSlash(repoRelativePath))
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	for _, docStem := range []string{
		"readme", "changelog", "changes", "contributing", "contributors",
		"license", "licence", "notice", "authors", "troubleshooting",
		"code_of_conduct", "code-of-conduct", "security", "history",
	} {
		if stem == docStem {
			return "docs"
		}
	}

	dirTags := map[string]string{
		"generated": "generated", "test": "test", "tests": "test",
		"__tests__": "test", "testing": "test", "testdata": "test",
		"fixture": "fixture", "fixtures": "fixture", "testfixtures": "fixture",
		"docs": "docs", "documentation": "docs", "doc": "docs",
		"examples": "example", "example": "example", "samples": "example",
		".github": "ci", "ci": "ci", ".circleci": "ci", ".azure-pipelines": "ci",
		"scripts": "build", "script": "build", "tools": "build",
		"deploy": "deployment", "deployment": "deployment", "infra": "deployment",
		"terraform": "deployment", "helm": "deployment", "k8s": "deployment",
		"build": "build",
		"vendor": "vendored", "third_party": "vendored", "third-party": "vendored", "external": "vendored",
	}
	for _, part := range strings.Split(path, "/") {
		if label, ok := dirTags[part]; ok {
			return label
		}
	}
	return "production"
}

// LookupFileOwnership returns the canonical ownership for a repo-relative
// POSIX path. If the exact path is not in the precomputed map, it walks up
// the directory hierarchy looking for any parent whose ownership is known,
// then falls back to repo-global.
func LookupFileOwnership(plan *ScanPlan, relPath string) *FileOwnership {
	relPath = filepath.ToSlash(filepath.Clean(relPath))
	if fo := plan.FileOwnership[relPath]; fo != nil {
		return fo
	}
	dir := relPath
	for {
		parent := filepath.ToSlash(filepath.Dir(dir))
		if parent == dir || parent == "." || parent == "" {
			break
		}
		dir = parent
		if fo := plan.FileOwnership[dir]; fo != nil {
			return &FileOwnership{
				ComponentIDs: fo.ComponentIDs,
				TargetIDs:    fo.TargetIDs,
				Relation:     fo.Relation,
				Context:      contextForPathLocal(relPath),
			}
		}
	}
	return &FileOwnership{
		Relation: RelationRepositoryGlobal,
		Context:  contextForPathLocal(relPath),
	}
}

func containsRoot(roots []string, wanted string) bool {
	for _, root := range roots {
		if filepath.Clean(root) == wanted {
			return true
		}
	}
	return false
}

func unitFiles(repoRoot, root string, inventory []InventoryEntry) ([]string, []string, []string) {
	var files, manifests, lockfiles []string
	for _, entry := range inventory {
		abs := filepath.Join(repoRoot, filepath.FromSlash(entry.Path))
		if !within(abs, root) {
			continue
		}
		files = append(files, entry.Path)
		if entry.Manifest {
			manifests = append(manifests, entry.Path)
		}
		if entry.Lockfile {
			lockfiles = append(lockfiles, entry.Path)
		}
	}
	return files, manifests, lockfiles
}
// unitEcosystems returns the set of Project.Ecosystem values for every
// project whose ownership root is exactly unitRoot -- i.e. which
// ecosystem(s) this physical scan unit actually represents.
func unitEcosystems(projects []*Project, unitRoot string) map[string]bool {
	result := make(map[string]bool)
	clean := filepath.Clean(unitRoot)
	for _, p := range projects {
		root := p.OwnershipRoot
		if root == "" {
			root = p.Dir
		}
		if filepath.Clean(root) == clean && p.Ecosystem != "" {
			result[p.Ecosystem] = true
		}
	}
	return result
}

// isExcludedFromUnit reports whether abs (an absolute path already known to
// be within unit.Root) falls under one of unit's own finalized ExcludedDirs.
func isExcludedFromUnit(unit *ScanUnit, abs string) bool {
	rel, err := filepath.Rel(unit.Root, abs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, excluded := range unit.ExcludedDirs {
		if rel == excluded || strings.HasPrefix(rel, excluded+"/") {
			return true
		}
	}
	return false
}

// unitHasOwnLockfile reports whether unit's own scan scope -- respecting its
// own (already-finalized) exclusions -- contains at least one lockfile of
// its own. A lockfile that only exists because of a foreign nested project
// unit.ExcludedDirs already prunes does not count: that file will never
// actually reach the scanner.
func unitHasOwnLockfile(repoRoot string, unit *ScanUnit, inventory []InventoryEntry) bool {
	for _, entry := range inventory {
		if !entry.Lockfile {
			continue
		}
		abs := filepath.Join(repoRoot, filepath.FromSlash(entry.Path))
		if !within(abs, unit.Root) {
			continue
		}
		if isExcludedFromUnit(unit, abs) {
			continue
		}
		return true
	}
	return false
}

// workspaceRootFallbackLockfiles returns the repo-root-level lockfile
// path(s) that should back up unit's own SCA scope, or nil when unit already
// has its own lockfile (the common case) or the repository root has no
// lockfile matching an ecosystem unit actually uses. Evidenced by real
// npm/yarn/pnpm workspaces, where every member's package.json shares one
// package-lock.json at the workspace root; Cargo workspaces follow the same
// pattern with one root Cargo.lock. Matching is ecosystem-aware so a Python
// unit is never backed by an unrelated root-level package-lock.json.
func workspaceRootFallbackLockfiles(resolution *Resolution, unit *ScanUnit) []string {
	ecosystems := unitEcosystems(resolution.Projects, unit.Root)
	if len(ecosystems) == 0 {
		return nil
	}
	if unitHasOwnLockfile(resolution.RepoRoot, unit, resolution.Inventory) {
		return nil
	}
	var fallback []string
	for _, entry := range resolution.Inventory {
		if !entry.Lockfile || filepath.ToSlash(filepath.Dir(entry.Path)) != "." {
			continue // only the repository root's own direct files qualify
		}
		eco := lockfileEcosystem(filepath.Base(entry.Path))
		if eco != "" && ecosystems[eco] {
			fallback = append(fallback, entry.Path)
		}
	}
	sort.Strings(fallback)
	return fallback
}

// applyWorkspaceRootFallbackOwnership attributes each workspace-root
// fallback lockfile (ScanUnit.FallbackLockfiles) to every target that relies
// on it, merging into whatever buildFileOwnership already computed. Without
// this, a finding from a repo-root lockfile would be attributed as
// unowned/repository-global purely because the file itself sits outside
// every target's own directory tree, even though it was fetched specifically
// on a target's behalf.
func applyWorkspaceRootFallbackOwnership(plan *ScanPlan, selected []*Target) {
	targetComponent := make(map[string]string, len(selected))
	for _, t := range selected {
		targetComponent[t.ID] = t.ComponentID
	}
	for _, unit := range plan.Units {
		if len(unit.FallbackLockfiles) == 0 {
			continue
		}
		var targetIDs, componentIDs []string
		for _, tid := range unit.TargetIDs {
			targetIDs = appendUniqueStr(targetIDs, tid)
			if cid := targetComponent[tid]; cid != "" {
				componentIDs = appendUniqueStr(componentIDs, cid)
			}
		}
		for _, path := range unit.FallbackLockfiles {
			fo := &FileOwnership{Relation: RelationWorkspaceRoot, Context: contextForPathLocal(path)}
			if existing := plan.FileOwnership[path]; existing != nil {
				fo.TargetIDs = appendUniqueStr(append([]string{}, existing.TargetIDs...), targetIDs...)
				fo.ComponentIDs = appendUniqueStr(append([]string{}, existing.ComponentIDs...), componentIDs...)
			} else {
				fo.TargetIDs = targetIDs
				fo.ComponentIDs = componentIDs
			}
			sort.Strings(fo.TargetIDs)
			sort.Strings(fo.ComponentIDs)
			plan.FileOwnership[path] = fo
		}
	}
}

func generatedRelativeExcludes(repoRoot string, options PlanOptions) []string {
	var result []string
	for _, value := range append([]string{options.OutputPath}, options.OutputDirs...) {
		if value == "" {
			continue
		}
		abs, err := filepath.Abs(value)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(repoRoot, abs)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			result = append(result, filepath.ToSlash(rel))
		}
	}
	return result
}
