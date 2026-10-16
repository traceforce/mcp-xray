package targetresolve

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mcpxray/internal/aggregation"
)

// Relation is how a scan unit or a file relates to a selected target.
type Relation string

const (
	// RelationDirect: the target's own project (for a unit), or a file only
	// one selected target uses (for a file).
	RelationDirect Relation = "direct"
	// RelationShared: a dependency of the target (for a unit), or a file
	// several selected targets use (for a file).
	RelationShared Relation = "shared"
	// RelationCompanion: a test project that depends on the target.
	RelationCompanion Relation = "companion"
	// RelationRepositoryGlobal: repository content no selected target owns.
	RelationRepositoryGlobal Relation = "repository-global"
	// RelationWorkspaceRoot: a workspace lockfile above a target's project
	// that pins the project's dependencies (see ScanUnit.FallbackLockfiles).
	RelationWorkspaceRoot Relation = "workspace-root-dependency"
)

// rank orders relations by how closely they tie content to a target, so the
// strongest wins when several apply. It follows InclusionReason.rank: a
// dependency's code outranks a test project's. RelationWorkspaceRoot is
// assigned directly to a fallback lockfile's record and never ranked.
func (r Relation) rank() int {
	switch r {
	case RelationDirect:
		return 4
	case RelationShared:
		return 3
	case RelationCompanion:
		return 2
	case RelationRepositoryGlobal:
		return 1
	}
	return 0
}

// ScanUnit is one directory that each selected scanner scans once. A unit
// may serve several targets.
type ScanUnit struct {
	ID           string              `json:"id"`
	Root         string              `json:"-"`
	RelativeRoot string              `json:"root"`
	TargetIDs    []string            `json:"targetIds,omitempty"`
	Relations    map[string]Relation `json:"relations,omitempty"`
	ExcludedDirs []string            `json:"excludedDirs,omitempty"`
	// Files lists the inventory files the unit's scanners read, those
	// outside its ExcludedDirs; Manifests and Lockfiles are its dependency
	// files. The dependency scan also reads dependency files in directories
	// the default exclusions skip, as a full scan's does, which no list names.
	Files     []string `json:"files,omitempty"`
	Manifests []string `json:"manifests,omitempty"`
	Lockfiles []string `json:"lockfiles,omitempty"`

	// FallbackLockfiles maps each workspace lockfile that pins a project
	// this unit scans for a selected target to the IDs of the targets
	// relying on it. It is the shared-workspace-lockfile pattern: a
	// workspace member declares its dependencies in its own manifest, but
	// only the lockfile at the workspace root, a directory above it, pins
	// their versions. The lockfile lies in this unit or above it, maybe in
	// no unit at all (ScanPlan.FallbackLockfileDirs).
	//
	// Every finding in such a lockfile is credited to each target relying
	// on it, although the lockfile pins the dependencies of the whole
	// workspace, of which one member uses only part.
	FallbackLockfiles map[string][]string `json:"fallbackLockfiles,omitempty"`
}

// FallbackLockfileDirs returns, sorted and repository-relative, the
// directory of every fallback lockfile (ScanUnit.FallbackLockfiles) that no
// unit scans: dependency scanning must also read that directory's own files
// on behalf of the targets relying on it.
func (p *ScanPlan) FallbackLockfileDirs() []string {
	var dirs []string
	for _, unit := range p.Units {
		for lockfile := range unit.FallbackLockfiles {
			if abs := filepath.Join(p.RepoRoot, filepath.FromSlash(lockfile)); !p.scans(abs) {
				dirs = append(dirs, repoRelative(p.RepoRoot, filepath.Dir(abs)))
			}
		}
	}
	return uniqueSorted(dirs)
}

// scans reports whether one of the plan's units scans the file at abs.
func (p *ScanPlan) scans(abs string) bool {
	for _, unit := range p.Units {
		if within(abs, unit.Root) && !isExcludedFromUnit(unit, abs) {
			return true
		}
	}
	return false
}

// PlanOptions selects the targets to plan and the paths to keep out of
// every scan.
type PlanOptions struct {
	TargetIDs         []string
	AllTargets        bool
	IncludeRepoGlobal bool
	OutputPath        string
	OutputDirs        []string
}

// ScanPlan is the set of scan units that together cover the selected
// targets, and the ownership of every inventoried file.
type ScanPlan struct {
	RepoRoot        string
	SelectedTargets []*Target
	Units           []*ScanUnit
	Inventory       []InventoryEntry
	Excluded        []string
	Unowned         []string
	Ambiguous       []string
	FileOwnership   map[string]*FileOwnership

	// IncludesRepoGlobal is set when the plan also covers the repository
	// content no selected target owns.
	IncludesRepoGlobal bool

	ownership ownershipModel
}

// Reports reports whether a finding credited to targetIDs belongs in the
// plan's report: a selected target owns its file, or the plan covers
// repository-global content. A unit reaches files no selected target owns
// only when it scans an unselected project that encloses a selected one.
func (p *ScanPlan) Reports(targetIDs []string) bool {
	return p.IncludesRepoGlobal || len(targetIDs) > 0
}

// TargetPlanView is a selected target as shown in ScanPlanView.
type TargetPlanView struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	ComponentID        string   `json:"componentId"`
	IncludedProjectIDs []string `json:"includedProjectIds"`
}

// ScanPlanView is the machine-readable form of a ScanPlan, with
// repository-relative paths.
type ScanPlanView struct {
	RepoRoot        string           `json:"repoRoot"`
	SelectedTargets []TargetPlanView `json:"selectedTargets"`
	Units           []*ScanUnit      `json:"scanUnits"`
	Inventory       []InventoryEntry `json:"inventory"`
	Excluded        []string         `json:"excluded,omitempty"`
	Unowned         []string         `json:"unowned,omitempty"`
	Ambiguous       []string         `json:"ambiguous,omitempty"`
}

// StructuredScanPlan returns the machine-readable view of plan.
func StructuredScanPlan(plan *ScanPlan) ScanPlanView {
	view := ScanPlanView{RepoRoot: ".", Units: plan.Units, Inventory: plan.Inventory, Excluded: plan.Excluded, Unowned: plan.Unowned, Ambiguous: plan.Ambiguous}
	for _, target := range plan.SelectedTargets {
		view.SelectedTargets = append(view.SelectedTargets, TargetPlanView{ID: target.ID, Name: target.Name, ComponentID: target.ComponentID, IncludedProjectIDs: target.IncludedProjectIDs})
	}
	return view
}

// buildInventory lists every file under repoRoot that the scanners see with
// their default exclusions, flags dependency manifests and lockfiles, and
// records which projects' (and components') scan roots contain each file,
// with the innermost of those roots as its Ownership. MCP X-Ray's own
// generated reports are returned separately as excluded.
func buildInventory(repoRoot string, projects []*Project) ([]InventoryEntry, []string, error) {
	var inventory []InventoryEntry
	var excluded []string
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		rel := repoRelative(repoRoot, path)
		if isGeneratedOutputPath(path) {
			excluded = append(excluded, rel)
			return nil
		}
		entry := InventoryEntry{Path: rel, Manifest: matchesManifest(info.Name()), Lockfile: matchesLockfile(info.Name()), Ownership: "unowned"}
		owner := ""
		for _, p := range projects {
			if root := p.ScanRoot(); p.claims(path) {
				entry.ProjectIDs = append(entry.ProjectIDs, p.ID)
				entry.ComponentIDs = append(entry.ComponentIDs, p.ComponentID)
				if len(root) > len(owner) {
					owner = root
				}
			}
		}
		if owner != "" {
			entry.Ownership = repoRelative(repoRoot, owner)
		}
		entry.ProjectIDs = uniqueSorted(entry.ProjectIDs)
		entry.ComponentIDs = uniqueSorted(entry.ComponentIDs)
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

// generatedOutputName matches the name of every file MCP X-Ray writes under
// a default name: the SARIF reports findings-<command>-<timestamp>.sarif.json
// and pentest's preliminary-findings-<server>-<timestamp>.sarif.json,
// config-scan's tools_summary_<timestamp>.json, and pentest's per-tool plans
// pentest_plan_<server>_<tool>_<timestamp>.yaml and their
// merged_test_plan.yaml. The timestamp is RFC 3339, in some names with its
// colons replaced by hyphens.
var generatedOutputName = regexp.MustCompile(fmt.Sprintf(
	`^(?:(?:preliminary-)?findings-.+-%[1]s\.sarif\.json|tools_summary_%[1]s\.json|pentest_plan_.+_%[1]s\.yaml|merged_test_plan\.yaml)$`,
	`\d{4}-\d{2}-\d{2}T\d{2}[-:]\d{2}[-:]\d{2}(?:Z|[+-]\d{2}[-:]\d{2})`))

// isGeneratedOutputPath reports whether path is a report MCP X-Ray wrote
// under its default name. Any other file is source, however it is named
// (findings_store.js, merged_tools.py); a report written to an explicit path
// is kept out of the scan by PlanOptions instead.
func isGeneratedOutputPath(path string) bool {
	return generatedOutputName.MatchString(filepath.Base(path))
}

func within(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// BuildScanPlan creates one scan unit per scan root of the selected targets
// (nested roots folded into the root enclosing them), plus the residual
// repository-global unit when requested, and records which targets own
// every inventoried file.
func BuildScanPlan(resolution *Resolution, options PlanOptions) (*ScanPlan, error) {
	if resolution == nil {
		return nil, fmt.Errorf("resolution is nil")
	}
	selected, err := selectTargets(resolution.Targets, options)
	if err != nil {
		return nil, err
	}

	units, roots := unitsForTargets(resolution.RepoRoot, selected)
	if options.IncludeRepoGlobal && !containsRoot(roots, filepath.Clean(resolution.RepoRoot)) {
		units = append(units, repositoryGlobalUnit(resolution.RepoRoot, selected, roots))
	}
	includedRoots := includedScanRoots(selected)
	for _, unit := range units {
		finalizeUnit(unit, resolution, selected, includedRoots, options)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].ID < units[j].ID })

	plan := &ScanPlan{RepoRoot: resolution.RepoRoot, SelectedTargets: selected, Units: units, Inventory: resolution.Inventory, IncludesRepoGlobal: options.IncludeRepoGlobal}
	plan.Unowned, plan.Excluded, plan.Ambiguous = scopeDiagnostics(resolution, options)
	plan.ownership = newOwnershipModel(resolution, selected)
	plan.FileOwnership = buildFileOwnership(resolution, plan.ownership)
	applyWorkspaceRootFallbackOwnership(plan, selected)
	return plan, nil
}

// scopeDiagnostics lists, sorted, the inventoried files no project owns,
// the paths kept out of every scan, and the projects whose ownership is
// ambiguous.
func scopeDiagnostics(resolution *Resolution, options PlanOptions) (unowned, excluded, ambiguous []string) {
	for _, entry := range resolution.Inventory {
		if entry.Ownership == "unowned" {
			unowned = append(unowned, entry.Path)
		}
	}
	sort.Strings(unowned)
	excluded = uniqueSorted(append(append([]string(nil), resolution.Excluded...), generatedRelativeExcludes(resolution.RepoRoot, options)...))
	for _, project := range resolution.Projects {
		if project.OwnershipAmbiguous {
			ambiguous = append(ambiguous, project.ID)
		}
	}
	sort.Strings(ambiguous)
	return unowned, excluded, ambiguous
}

// selectTargets returns the targets options asks for. Every requested ID
// must have been discovered, also when AllTargets selects them anyway.
func selectTargets(targets []*Target, options PlanOptions) ([]*Target, error) {
	requested := make(map[string]bool)
	for _, id := range options.TargetIDs {
		requested[id] = true
	}
	selected := make([]*Target, 0)
	discovered := make(map[string]bool, len(targets))
	for _, target := range targets {
		discovered[target.ID] = true
		if options.AllTargets || requested[target.ID] {
			selected = append(selected, target)
		}
	}
	var unknown []string
	for id := range requested {
		if !discovered[id] {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("target ID(s) not discovered: %q", unknown)
	}
	if len(selected) == 0 && !options.AllTargets {
		return nil, fmt.Errorf("no targets selected")
	}
	return selected, nil
}

// unitsForTargets creates one unit per scan root of the selected targets'
// included projects. A unit whose root lies inside another unit's root is
// folded into that enclosing unit, whose recursive scan already covers its
// files; its targets carry over so they keep a unit (and their own
// workspace-root fallback). roots are the remaining, non-nested unit roots.
func unitsForTargets(repoRoot string, selected []*Target) (units []*ScanUnit, roots []string) {
	byRoot := make(map[string]*ScanUnit)
	for _, target := range selected {
		for _, project := range target.Included {
			root := project.ScanRoot()
			unit := byRoot[root]
			if unit == nil {
				rel := repoRelative(repoRoot, root)
				unit = &ScanUnit{ID: stableID("scan", rel), Root: root, RelativeRoot: rel, Relations: map[string]Relation{}}
				byRoot[root] = unit
				roots = append(roots, root)
			}
			unit.addTarget(target.ID, target.relationOf(project))
		}
	}
	roots = dropNestedRoots(roots)
	for _, root := range roots {
		units = append(units, byRoot[root])
	}
	for root, unit := range byRoot {
		if containsRoot(roots, root) {
			continue
		}
		for _, enclosing := range roots {
			if within(root, enclosing) {
				for _, targetID := range unit.TargetIDs {
					byRoot[enclosing].addTarget(targetID, unit.Relations[targetID])
				}
				break
			}
		}
	}
	return units, roots
}

// addTarget records that the unit serves targetID, keeping the strongest
// relation when the target reaches the unit more than once.
func (u *ScanUnit) addTarget(targetID string, relation Relation) {
	u.TargetIDs = appendUniqueStr(u.TargetIDs, targetID)
	if relation.rank() > u.Relations[targetID].rank() {
		u.Relations[targetID] = relation
	}
}

// relationOf is how one of the target's included projects relates to it.
func (t *Target) relationOf(p *Project) Relation {
	switch {
	case p == t.Project:
		return RelationDirect
	case t.IncludedReasons[filepath.Clean(p.Dir)] == InclusionTestDependent:
		return RelationCompanion
	}
	return RelationShared
}

// repositoryGlobalUnit covers the repository content outside every scheduled
// root, once, for all selected targets. It excludes only those roots, so
// discovered-but-unselected projects stay visible to it.
func repositoryGlobalUnit(repoRoot string, selected []*Target, roots []string) *ScanUnit {
	unit := &ScanUnit{ID: stableID("scan", "."), Root: repoRoot, RelativeRoot: ".", Relations: map[string]Relation{}, ExcludedDirs: residualExcludes(repoRoot, roots)}
	for _, target := range selected {
		unit.addTarget(target.ID, RelationRepositoryGlobal)
	}
	return unit
}

// includedScanRoots is every scan root any selected target includes. A unit
// may have absorbed another target's nested root, so foreign-project
// exclusion must consult all of them, not just the unit's own.
func includedScanRoots(selected []*Target) map[string]bool {
	roots := make(map[string]bool)
	for _, target := range selected {
		for _, project := range target.Included {
			roots[project.ScanRoot()] = true
		}
	}
	return roots
}

// finalizeUnit fills in the unit's exclusions and then the files it scans,
// and decides which workspace lockfiles the unit's targets rely on. A unit
// always excludes generated reports. It also excludes every discovered
// project nested in it that no selected target includes
// (nestedForeignExcludes), unless the plan includes repository-global
// content: the unit is then the one scan that covers those projects, whose
// files no target owns (ownershipModel.of).
func finalizeUnit(unit *ScanUnit, resolution *Resolution, selected []*Target, includedRoots map[string]bool, options PlanOptions) {
	sort.Strings(unit.TargetIDs)
	unit.ExcludedDirs = append(unit.ExcludedDirs, generatedRelativeExcludes(unit.Root, options)...)
	if !options.IncludeRepoGlobal {
		unit.ExcludedDirs = append(unit.ExcludedDirs, nestedForeignExcludes(unit.Root, includedRoots, resolution.Projects)...)
	}
	for _, excluded := range resolution.Excluded {
		abs := filepath.Join(resolution.RepoRoot, filepath.FromSlash(excluded))
		if within(abs, unit.Root) && abs != filepath.Clean(unit.Root) {
			unit.ExcludedDirs = append(unit.ExcludedDirs, repoRelative(unit.Root, abs))
		}
	}
	unit.ExcludedDirs = uniqueSorted(unit.ExcludedDirs)
	unit.Files, unit.Manifests, unit.Lockfiles = unitFiles(resolution.RepoRoot, unit, resolution.Inventory)
	unit.FallbackLockfiles = workspaceRootFallbackLockfiles(resolution, selected, unit)
}

// buildComponentRelations gives each component used by a selected target its
// relation: shared when several selected targets use it, companion when its
// only user includes it as a test dependent, direct otherwise.
func buildComponentRelations(targets []*Target) map[string]Relation {
	usage := make(map[string]map[string]InclusionReason)
	for _, target := range targets {
		for _, project := range target.Included {
			cid := project.ComponentID
			if usage[cid] == nil {
				usage[cid] = make(map[string]InclusionReason)
			}
			reason := target.IncludedReasons[filepath.Clean(project.Dir)]
			if existing, seen := usage[cid][target.ID]; !seen || reason.rank() > existing.rank() {
				usage[cid][target.ID] = reason
			}
		}
	}

	relations := make(map[string]Relation, len(usage))
	for cid, targetReasons := range usage {
		relations[cid] = RelationDirect
		if len(targetReasons) > 1 {
			relations[cid] = RelationShared
			continue
		}
		for _, reason := range targetReasons {
			if reason == InclusionTestDependent {
				relations[cid] = RelationCompanion
			}
		}
	}
	return relations
}

// ownershipModel decides which components and selected targets own a
// file from the components whose roots contain it.
type ownershipModel struct {
	repoRoot           string
	components         []*Component
	rootDepth          map[string]int // component ID -> length of its root
	componentTargets   map[string][]string
	componentRelations map[string]Relation
}

func newOwnershipModel(resolution *Resolution, selected []*Target) ownershipModel {
	model := ownershipModel{
		repoRoot:           resolution.RepoRoot,
		components:         resolution.Components,
		rootDepth:          make(map[string]int, len(resolution.Components)),
		componentTargets:   make(map[string][]string),
		componentRelations: buildComponentRelations(selected),
	}
	for _, component := range resolution.Components {
		model.rootDepth[component.ID] = len(filepath.Clean(component.Root))
	}
	for _, target := range selected {
		for _, project := range target.Included {
			model.componentTargets[project.ComponentID] = appendUniqueStr(model.componentTargets[project.ComponentID], target.ID)
		}
	}
	return model
}

// of is the ownership of the file at the repository-relative path rel that
// the components componentIDs contain. The file belongs to the innermost of
// them, the project nearest to it, not to every project enclosing that
// one: a Go module nested in another, or an unselected project inside a
// target's directory, is not the enclosing project's code. That component
// gives the file its selected targets and relation.
func (m ownershipModel) of(rel string, componentIDs []string) *FileOwnership {
	owners := m.innermost(componentIDs)
	fo := &FileOwnership{
		ComponentIDs: owners,
		Relation:     RelationRepositoryGlobal,
		Context:      aggregation.ContextForPath(rel),
	}
	for _, cid := range owners {
		fo.TargetIDs = appendUniqueStr(fo.TargetIDs, m.componentTargets[cid]...)
		if relation := m.componentRelations[cid]; relation.rank() > fo.Relation.rank() {
			fo.Relation = relation
		}
	}
	sort.Strings(fo.TargetIDs)
	sort.Strings(fo.ComponentIDs)
	return fo
}

// innermost keeps, of componentIDs (components whose roots all lie on the
// path to one file), the one with the deepest root. Components the model
// does not know are kept as they are.
func (m ownershipModel) innermost(componentIDs []string) []string {
	deepest := -1
	for _, cid := range componentIDs {
		if d, ok := m.rootDepth[cid]; ok && d > deepest {
			deepest = d
		}
	}
	var owners []string
	for _, cid := range componentIDs {
		if d, ok := m.rootDepth[cid]; !ok || d == deepest {
			owners = append(owners, cid)
		}
	}
	return owners
}

// componentsContaining returns the IDs of the components whose root holds
// the file at the repository-relative path rel.
func (m ownershipModel) componentsContaining(rel string) []string {
	abs := filepath.Join(m.repoRoot, filepath.FromSlash(rel))
	var ids []string
	for _, component := range m.components {
		if within(abs, component.Root) {
			ids = append(ids, component.ID)
		}
	}
	return ids
}

// buildFileOwnership records the ownership of every inventoried file, keyed
// by its repository-relative POSIX path.
func buildFileOwnership(resolution *Resolution, model ownershipModel) map[string]*FileOwnership {
	ownership := make(map[string]*FileOwnership, len(resolution.Inventory))
	for _, entry := range resolution.Inventory {
		ownership[entry.Path] = model.of(entry.Path, entry.ComponentIDs)
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

// OwnershipOf returns the ownership of file, given as an absolute path or
// relative to the repository root. A file outside the inventory, in a
// directory the default exclusions skip (a lockfile the dependency scan
// reads there, or any file when the run turned the exclusions off), is
// owned by the components whose roots contain it.
func (p *ScanPlan) OwnershipOf(file string) FileOwnership {
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(p.RepoRoot, file); err == nil {
			rel = r
		}
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if ownership := p.FileOwnership[rel]; ownership != nil {
		return *ownership
	}
	return *p.ownership.of(rel, p.ownership.componentsContaining(rel))
}

// TargetSummaries describes every selected target -- including one with no
// findings -- with the units that scan it and its finding counts.
func (p *ScanPlan) TargetSummaries(rawFindings, uniqueFindings map[string]int) []TargetSummary {
	summaries := make([]TargetSummary, 0, len(p.SelectedTargets))
	for _, target := range p.SelectedTargets {
		var unitIDs []string
		for _, unit := range p.Units {
			if containsString(unit.TargetIDs, target.ID) {
				unitIDs = append(unitIDs, unit.ID)
			}
		}
		summaries = append(summaries, TargetSummary{
			TargetID:       target.ID,
			Name:           target.Name,
			ProjectID:      target.Project.ID,
			ComponentID:    target.ComponentID,
			OwnershipRoot:  repoRelative(p.RepoRoot, target.Project.ScanRoot()),
			ScanUnitIDs:    unitIDs,
			RawFindings:    rawFindings[target.ID],
			UniqueFindings: uniqueFindings[target.ID],
		})
	}
	return summaries
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsRoot(roots []string, wanted string) bool {
	for _, root := range roots {
		if filepath.Clean(root) == wanted {
			return true
		}
	}
	return false
}

// unitFiles lists the inventoried files the unit's scan reads, those under
// its root and outside its ExcludedDirs, and the dependency manifests and
// lockfiles among them.
func unitFiles(repoRoot string, unit *ScanUnit, inventory []InventoryEntry) (files, manifests, lockfiles []string) {
	for _, entry := range inventory {
		abs := filepath.Join(repoRoot, filepath.FromSlash(entry.Path))
		if !within(abs, unit.Root) || isExcludedFromUnit(unit, abs) {
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

// workspaceRootFallbackLockfiles returns each workspace lockfile that a
// project in unit relies on, mapped to the IDs of the selected targets that
// include the project. A project a target includes inside this unit (and
// not pruned from it) relies on one when no lockfile of its own ecosystem
// family pins it (hasOwnLockfile): it then relies on the lockfiles that can
// pin it (rootLockfileCanPin) as a member of their workspace
// (workspaceMembership) in the nearest directory above it holding any, up
// to the repository root. The decision is made per project and per
// family: a Python package's uv.lock says nothing about the Node package
// next to it, and a nested project's own lockfile says nothing about the
// project enclosing it. It does not depend on where the lockfile is
// scanned -- in this unit, in an enclosing one, or on its own
// (ScanPlan.FallbackLockfileDirs) -- so neither does which targets are
// credited with it. Only projects a target actually includes count:
// anything else under the unit merely shares its directory (a client
// script beside a server, say) and must not pull unrelated lockfiles into
// that target's results.
func workspaceRootFallbackLockfiles(resolution *Resolution, selected []*Target, unit *ScanUnit) map[string][]string {
	lockfilesByDir := make(map[string][]string) // absolute directory -> its lockfiles' repository-relative paths
	var unitLockfiles []string
	for _, entry := range resolution.Inventory {
		if !entry.Lockfile {
			continue
		}
		abs := filepath.Join(resolution.RepoRoot, filepath.FromSlash(entry.Path))
		lockfilesByDir[filepath.Dir(abs)] = append(lockfilesByDir[filepath.Dir(abs)], entry.Path)
		if within(abs, unit.Root) && !isExcludedFromUnit(unit, abs) {
			unitLockfiles = append(unitLockfiles, abs) // only files that actually reach this unit's scanner
		}
	}
	var projectRoots []string
	for _, project := range resolution.Projects {
		if !project.EmbeddedScript { // its directory holds the enclosing project's lockfiles
			projectRoots = append(projectRoots, project.ScanRoot())
		}
	}

	members := newWorkspaceMembership(resolution.RepoRoot)
	needed := make(map[string][]string)
	for _, target := range selected {
		if !containsString(unit.TargetIDs, target.ID) {
			continue
		}
		for _, project := range target.Included {
			root := project.ScanRoot()
			if !within(root, unit.Root) || isExcludedFromUnit(unit, root) {
				continue
			}
			family := ecosystemFamily(project.Ecosystem)
			if family == "" || hasOwnLockfile(unitLockfiles, family, root, projectRoots) {
				continue
			}
			for _, lockfile := range nearestWorkspaceLockfiles(lockfilesByDir, resolution.RepoRoot, project, members) {
				needed[lockfile] = appendUniqueStr(needed[lockfile], target.ID)
			}
		}
	}
	if len(needed) == 0 {
		return nil
	}
	return needed
}

// hasOwnLockfile reports whether one of lockfiles (absolute paths) of the
// given ecosystem family belongs to the project rooted at root: it lies in
// the project's own tree, and in no other project nested there.
func hasOwnLockfile(lockfiles []string, family, root string, projectRoots []string) bool {
	for _, lockfile := range lockfiles {
		if lockfileEcosystem(filepath.Base(lockfile)) == family && within(lockfile, root) && !insideNestedProject(lockfile, root, projectRoots) {
			return true
		}
	}
	return false
}

// nearestWorkspaceLockfiles returns the lockfiles of lockfilesByDir that can
// pin project (rootLockfileCanPin) as a member of their workspace (members)
// and lie in the nearest directory above its scan root, up to repoRoot,
// holding any.
func nearestWorkspaceLockfiles(lockfilesByDir map[string][]string, repoRoot string, project *Project, members *workspaceMembership) []string {
	repoRoot = filepath.Clean(repoRoot)
	for dir := project.ScanRoot(); dir != repoRoot && within(dir, repoRoot); {
		dir = filepath.Dir(dir)
		var found []string
		for _, lockfile := range lockfilesByDir[dir] {
			if name := filepath.Base(lockfile); rootLockfileCanPin(name, project.Ecosystem) && members.includes(dir, name, project) {
				found = append(found, lockfile)
			}
		}
		if len(found) > 0 {
			return found
		}
	}
	return nil
}

// insideNestedProject reports whether path lies inside some project root
// nested strictly below root.
func insideNestedProject(path, root string, projectRoots []string) bool {
	for _, other := range projectRoots {
		if other != root && within(other, root) && within(path, other) {
			return true
		}
	}
	return false
}

// applyWorkspaceRootFallbackOwnership credits each workspace lockfile some
// unit's targets rely on (ScanUnit.FallbackLockfiles) to exactly those
// targets, on top of buildFileOwnership's record. The file lies outside
// their own trees, so its record would not name them.
func applyWorkspaceRootFallbackOwnership(plan *ScanPlan, selected []*Target) {
	targetComponent := make(map[string]string, len(selected))
	for _, t := range selected {
		targetComponent[t.ID] = t.ComponentID
	}
	for _, unit := range plan.Units {
		for path, reliantTargetIDs := range unit.FallbackLockfiles {
			var targetIDs, componentIDs []string
			for _, tid := range reliantTargetIDs {
				targetIDs = appendUniqueStr(targetIDs, tid)
				if cid := targetComponent[tid]; cid != "" {
					componentIDs = appendUniqueStr(componentIDs, cid)
				}
			}
			fo := &FileOwnership{Relation: RelationWorkspaceRoot, Context: aggregation.ContextForPath(path)}
			if existing := plan.FileOwnership[path]; existing != nil {
				fo.TargetIDs = appendUniqueStr(append([]string{}, existing.TargetIDs...), targetIDs...)
				fo.ComponentIDs = appendUniqueStr(append([]string{}, existing.ComponentIDs...), componentIDs...)
				if len(existing.TargetIDs) > 0 {
					// A selected target's own lockfile: as in ownershipModel.of,
					// the file keeps the strongest of its relations.
					fo.Relation = existing.Relation
				}
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

// resolveSymlinks returns the absolute path with its symlinks resolved, as
// the repository root is (a report given as -o through a symlinked checkout
// lies in it all the same). A path not written yet is resolved through its
// nearest existing ancestor.
func resolveSymlinks(path string) string {
	rest := ""
	for dir := path; ; dir = filepath.Dir(dir) {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		if filepath.Dir(dir) == dir {
			return path
		}
		rest = filepath.Join(filepath.Base(dir), rest)
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
		abs = resolveSymlinks(abs)
		if within(abs, repoRoot) && abs != filepath.Clean(repoRoot) {
			result = append(result, repoRelative(repoRoot, abs))
		}
	}
	return result
}
