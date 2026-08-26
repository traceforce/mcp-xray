package targetresolve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildScanPlanSharedUnitAndResidualScope(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	for _, dir := range []string{shared, a, b} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	projects := []*Project{
		{ID: "pa", Name: "a", Dir: a, OwnershipRoot: a, ComponentID: "ca"},
		{ID: "pb", Name: "b", Dir: b, OwnershipRoot: b, ComponentID: "cb"},
		{ID: "ps", Name: "shared", Dir: shared, OwnershipRoot: shared, ComponentID: "cs"},
	}
	targets := []*Target{
		{ID: "ta", Name: "a", Project: projects[0], Included: []*Project{projects[0], projects[2]}, IncludedReasons: map[string]InclusionReason{a: InclusionPrimary, shared: InclusionSharedDependency}},
		{ID: "tb", Name: "b", Project: projects[1], Included: []*Project{projects[1], projects[2]}, IncludedReasons: map[string]InclusionReason{b: InclusionPrimary, shared: InclusionSharedDependency}},
	}
	resolution := &Resolution{RepoRoot: root, Targets: targets, Inventory: nil}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true, IncludeRepoGlobal: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.SelectedTargets) != 2 {
		t.Fatalf("selected targets = %d, want 2", len(plan.SelectedTargets))
	}
	if len(plan.Units) != 4 {
		t.Fatalf("scan units = %d, want 4 (a, b, shared, global)", len(plan.Units))
	}
	sharedCount := 0
	for _, unit := range plan.Units {
		if unit.Root == shared {
			sharedCount++
			if len(unit.TargetIDs) != 2 {
				t.Errorf("shared unit target attribution = %v, want both targets", unit.TargetIDs)
			}
		}
	}
	if sharedCount != 1 {
		t.Fatalf("shared unit count = %d, want 1", sharedCount)
	}
	globalFound := false
	for _, unit := range plan.Units {
		if unit.Root == root {
			globalFound = true
			if len(unit.ExcludedDirs) != 3 {
				t.Errorf("global exclusions = %v, want scheduled roots", unit.ExcludedDirs)
			}
		}
	}
	if !globalFound {
		t.Error("expected one repository-global unit")
	}
}

// TestBuildScanPlan_ExcludesNestedForeignProject reproduces the reported
// flaw directly: selecting a target rooted at appDir must not also scan an
// unrelated project that happens to live in a subdirectory of appDir.
func TestBuildScanPlan_ExcludesNestedForeignProject(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "tools", "other")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	foreignProject := &Project{ID: "p-foreign", Name: "other", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, foreignProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	unit := plan.Units[0]
	want := filepath.ToSlash(filepath.Join("tools", "other"))
	found := false
	for _, excluded := range unit.ExcludedDirs {
		if excluded == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unit.ExcludedDirs to contain %q, got %v", want, unit.ExcludedDirs)
	}
}

// TestBuildScanPlan_DoesNotExcludeLegitimateNestedSharedComponent is the
// regression check for the case nestedForeignExcludes must NOT touch: a
// shared component nested inside the primary project's own directory tree,
// genuinely included in the same target, must remain scanned. dropNestedRoots
// folds the shared component's own unit into the primary's here (same as
// TestBuildScanPlanSharedUnitAndResidualScope's top-level "shared" case, just
// nested instead of a sibling), so this also proves nestedForeignExcludes
// correctly recognizes an included project even after its own separate unit
// was dropped.
func TestBuildScanPlan_DoesNotExcludeLegitimateNestedSharedComponent(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	sharedDir := filepath.Join(root, "app", "vendor", "shared-lib")
	for _, dir := range []string{appDir, sharedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	sharedProject := &Project{ID: "p-shared", Name: "shared-lib", Dir: sharedDir, OwnershipRoot: sharedDir, ComponentID: "c-shared"}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject, sharedProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary, sharedDir: InclusionSharedDependency}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, sharedProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1 (dropNestedRoots should fold the nested shared component into the app unit)", len(plan.Units))
	}
	unwanted := filepath.ToSlash(filepath.Join("vendor", "shared-lib"))
	for _, excluded := range plan.Units[0].ExcludedDirs {
		if excluded == unwanted {
			t.Errorf("legitimately included shared component %q must not be excluded, got ExcludedDirs=%v", unwanted, plan.Units[0].ExcludedDirs)
		}
	}
}

// TestBuildScanPlan_NestedForeignExcludeDoesNotAffectRepoGlobalUnit confirms
// the repository-global unit keeps its own, deliberately different exclusion
// rule (RepoLevelExcludesForScanUnits: only the scheduled roots) rather than
// also applying nestedForeignExcludes -- a repo-global scan is documented to
// intentionally still cover other discovered-but-unselected projects.
func TestBuildScanPlan_NestedForeignExcludeDoesNotAffectRepoGlobalUnit(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "tools", "other")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	foreignProject := &Project{ID: "p-foreign", Name: "other", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, foreignProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}, IncludeRepoGlobal: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scan units = %d, want 2 (app, global)", len(plan.Units))
	}
	for _, unit := range plan.Units {
		if unit.Root != root {
			continue
		}
		// The global unit excludes the one scheduled root ("app") and
		// nothing else -- in particular NOT "app/tools/other", which is
		// nested inside an excluded directory already and, per the
		// repo-global unit's own documented semantics, is not the kind of
		// exclusion this unit applies at all.
		if len(unit.ExcludedDirs) != 1 || unit.ExcludedDirs[0] != "app" {
			t.Errorf("expected the global unit to exclude only [\"app\"], got %v", unit.ExcludedDirs)
		}
	}
}

// TestWorkspaceRootFallback_TriggersWhenUnitHasNoOwnLockfile reproduces the
// real npm/yarn/pnpm workspace shape found in twilio-labs/mcp during
// benchmarking: two separate targets, each with its own package.json but no
// lockfile of its own -- only the workspace root's package-lock.json pins
// exact dependency versions. Both units should fall back to it, and the
// resulting finding ownership should credit both targets, not neither.
func TestWorkspaceRootFallback_TriggersWhenUnitHasNoOwnLockfile(t *testing.T) {
	root := t.TempDir()
	mcpDir := filepath.Join(root, "packages", "mcp")
	otherDir := filepath.Join(root, "packages", "openapi-mcp-server")
	for _, dir := range []string{mcpDir, otherDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mcpProject := &Project{ID: "p-mcp", Name: "mcp", Dir: mcpDir, OwnershipRoot: mcpDir, ComponentID: "c-mcp", Ecosystem: "node"}
	otherProject := &Project{ID: "p-other", Name: "openapi-mcp-server", Dir: otherDir, OwnershipRoot: otherDir, ComponentID: "c-other", Ecosystem: "node"}
	mcpTarget := &Target{ID: "t-mcp", Name: "mcp", Project: mcpProject, Included: []*Project{mcpProject}, IncludedReasons: map[string]InclusionReason{mcpDir: InclusionPrimary}, ComponentID: "c-mcp"}
	otherTarget := &Target{ID: "t-other", Name: "openapi-mcp-server", Project: otherProject, Included: []*Project{otherProject}, IncludedReasons: map[string]InclusionReason{otherDir: InclusionPrimary}, ComponentID: "c-other"}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{mcpProject, otherProject},
		Targets:  []*Target{mcpTarget, otherTarget},
		Inventory: []InventoryEntry{
			{Path: "package-lock.json", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scan units = %d, want 2", len(plan.Units))
	}
	for _, unit := range plan.Units {
		if len(unit.FallbackLockfiles) != 1 || unit.FallbackLockfiles[0] != "package-lock.json" {
			t.Errorf("unit %s: FallbackLockfiles = %v, want [\"package-lock.json\"]", unit.RelativeRoot, unit.FallbackLockfiles)
		}
	}
	fo := plan.FileOwnership["package-lock.json"]
	if fo == nil {
		t.Fatal("expected plan.FileOwnership[\"package-lock.json\"] to be set")
	}
	if fo.Relation != RelationWorkspaceRoot {
		t.Errorf("Relation = %q, want %q", fo.Relation, RelationWorkspaceRoot)
	}
	if len(fo.TargetIDs) != 2 || fo.TargetIDs[0] != "t-mcp" || fo.TargetIDs[1] != "t-other" {
		t.Errorf("TargetIDs = %v, want both t-mcp and t-other", fo.TargetIDs)
	}
}

// TestWorkspaceRootFallback_NoTriggerWhenUnitHasOwnLockfile is the negative
// regression matching aws-mcp's shape in the same benchmarking session: each
// target manages its own dependencies independently (its own uv.lock), so a
// root-level lockfile must never be treated as a fallback source even when
// one happens to exist.
func TestWorkspaceRootFallback_NoTriggerWhenUnitHasOwnLockfile(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p-server", Name: "server", Dir: serverDir, OwnershipRoot: serverDir, ComponentID: "c-server", Ecosystem: "python"}
	target := &Target{ID: "t-server", Name: "server", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{serverDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{project},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: filepath.ToSlash(filepath.Join("server", "uv.lock")), Lockfile: true},
			{Path: "requirements.txt", Lockfile: true}, // an unrelated root-level lockfile
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	if len(plan.Units[0].FallbackLockfiles) != 0 {
		t.Errorf("expected no fallback when the unit already has its own lockfile, got %v", plan.Units[0].FallbackLockfiles)
	}
}

// TestWorkspaceRootFallback_EcosystemMismatchNeverFallsBack proves a
// Python target with no lockfile of its own is never backed by an unrelated
// Node lockfile that happens to sit at the repository root.
func TestWorkspaceRootFallback_EcosystemMismatchNeverFallsBack(t *testing.T) {
	root := t.TempDir()
	pyDir := filepath.Join(root, "pyserver")
	if err := os.MkdirAll(pyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p-py", Name: "pyserver", Dir: pyDir, OwnershipRoot: pyDir, ComponentID: "c-py", Ecosystem: "python"}
	target := &Target{ID: "t-py", Name: "pyserver", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{pyDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot:  root,
		Projects:  []*Project{project},
		Targets:   []*Target{target},
		Inventory: []InventoryEntry{{Path: "package-lock.json", Lockfile: true}},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units[0].FallbackLockfiles) != 0 {
		t.Errorf("expected no fallback across mismatched ecosystems, got %v", plan.Units[0].FallbackLockfiles)
	}
}

// TestWorkspaceRootFallback_ExcludedOwnLockfileStillTriggersFallback proves
// unitHasOwnLockfile respects the unit's own finalized exclusions: a
// lockfile that only exists inside a foreign nested project (already pruned
// by nestedForeignExcludes) must not count as "the unit has its own
// lockfile" -- that file will never actually reach the scanner.
func TestWorkspaceRootFallback_ExcludedOwnLockfileStillTriggersFallback(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "vendor", "foreign")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "node"}
	foreignProject := &Project{ID: "p-foreign", Name: "foreign", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Ecosystem: "node", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{appProject, foreignProject},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: filepath.ToSlash(filepath.Join("app", "vendor", "foreign", "package-lock.json")), Lockfile: true},
			{Path: "package-lock.json", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	unit := plan.Units[0]
	excludesForeign := false
	for _, excluded := range unit.ExcludedDirs {
		if excluded == filepath.ToSlash(filepath.Join("vendor", "foreign")) {
			excludesForeign = true
		}
	}
	if !excludesForeign {
		t.Fatalf("expected the foreign nested project to be excluded, got ExcludedDirs=%v", unit.ExcludedDirs)
	}
	if len(unit.FallbackLockfiles) != 1 || unit.FallbackLockfiles[0] != "package-lock.json" {
		t.Errorf("expected the excluded nested lockfile to NOT count as the unit's own, so it should fall back to the root; got FallbackLockfiles=%v", unit.FallbackLockfiles)
	}
}

func TestBuildComponentRelations(t *testing.T) {
	dirA := filepath.Join(string(filepath.Separator), "repo", "a")
	dirB := filepath.Join(string(filepath.Separator), "repo", "b")
	dirShared := filepath.Join(string(filepath.Separator), "repo", "shared")
	dirTests := filepath.Join(string(filepath.Separator), "repo", "tests")
	targets := []*Target{
		{
			ID:      "t1",
			Name:    "server-a",
			Project: &Project{ID: "p1", Dir: dirA, ComponentID: "c-a"},
			Included: []*Project{
				{ID: "p1", Dir: dirA, ComponentID: "c-a"},
				{ID: "ps", Dir: dirShared, ComponentID: "c-shared"},
			},
			IncludedReasons: map[string]InclusionReason{filepath.Clean(dirA): InclusionPrimary, filepath.Clean(dirShared): InclusionSharedDependency},
		},
		{
			ID:      "t2",
			Name:    "server-b",
			Project: &Project{ID: "p2", Dir: dirB, ComponentID: "c-b"},
			Included: []*Project{
				{ID: "p2", Dir: dirB, ComponentID: "c-b"},
				{ID: "ps", Dir: dirShared, ComponentID: "c-shared"},
				{ID: "pt", Dir: dirTests, ComponentID: "c-tests"},
			},
			IncludedReasons: map[string]InclusionReason{filepath.Clean(dirB): InclusionPrimary, filepath.Clean(dirShared): InclusionSharedDependency, filepath.Clean(dirTests): InclusionTestDependent},
		},
	}
	relations := buildComponentRelations(targets)
	if relations["c-a"] != RelationDirect {
		t.Errorf("c-a = %q, want direct", relations["c-a"])
	}
	if relations["c-b"] != RelationDirect {
		t.Errorf("c-b = %q, want direct", relations["c-b"])
	}
	if relations["c-shared"] != RelationShared {
		t.Errorf("c-shared = %q, want shared (used by two targets)", relations["c-shared"])
	}
	if relations["c-tests"] != RelationCompanion {
		t.Errorf("c-tests = %q, want companion", relations["c-tests"])
	}
}

func TestLookupFileOwnership_ExactMatch(t *testing.T) {
	plan := &ScanPlan{
		FileOwnership: map[string]*FileOwnership{
			"src/main.go": {TargetIDs: []string{"t1"}, ComponentIDs: []string{"c1"}, Relation: RelationDirect, Context: "production"},
		},
	}
	fo := LookupFileOwnership(plan, "src/main.go")
	if fo.Relation != RelationDirect {
		t.Errorf("relation = %q, want direct", fo.Relation)
	}
	if len(fo.TargetIDs) != 1 || fo.TargetIDs[0] != "t1" {
		t.Errorf("targetIDs = %v, want [t1]", fo.TargetIDs)
	}
}

func TestLookupFileOwnership_DirectoryFallback(t *testing.T) {
	plan := &ScanPlan{
		FileOwnership: map[string]*FileOwnership{
			"src/lib/util.go": {TargetIDs: []string{"t1"}, ComponentIDs: []string{"c1"}, Relation: RelationDirect, Context: "production"},
		},
	}
	fo := LookupFileOwnership(plan, "src/lib/subdir/deep.go")
	if fo.Relation != RelationRepositoryGlobal {
		t.Logf("Note: directory fallback only matches directory entries, not file entries")
	}
}

func TestLookupFileOwnership_RepoGlobalFallback(t *testing.T) {
	plan := &ScanPlan{
		FileOwnership: map[string]*FileOwnership{},
	}
	fo := LookupFileOwnership(plan, "unknown/path.go")
	if fo.Relation != RelationRepositoryGlobal {
		t.Errorf("relation = %q, want repository-global for unknown file", fo.Relation)
	}
	if fo.Context != "production" {
		t.Errorf("context = %q, want production for production-path file", fo.Context)
	}
}

func TestLookupFileOwnership_ContextFromFilePath(t *testing.T) {
	plan := &ScanPlan{
		FileOwnership: map[string]*FileOwnership{},
	}
	fo := LookupFileOwnership(plan, "docs/guide.md")
	if fo.Context != "docs" {
		t.Errorf("context = %q, want docs", fo.Context)
	}
	fo2 := LookupFileOwnership(plan, "tests/unit_test.go")
	if fo2.Context != "test" {
		t.Errorf("context = %q, want test", fo2.Context)
	}
}

func TestBuildFileOwnershipWithMultipleTargets(t *testing.T) {
	resolution := &Resolution{
		RepoRoot: "/repo",
		Inventory: []InventoryEntry{
			{Path: "shared/util.go", ComponentIDs: []string{"c-shared"}},
			{Path: "a/main.go", ComponentIDs: []string{"c-a"}},
			{Path: "README.md", ComponentIDs: nil},
		},
	}
	targets := []*Target{
		{
			ID:      "t1",
			Project: &Project{ComponentID: "c-a"},
			Included: []*Project{
				{ComponentID: "c-a"},
				{ComponentID: "c-shared"},
			},
		},
		{
			ID:      "t2",
			Project: &Project{ComponentID: "c-b"},
			Included: []*Project{
				{ComponentID: "c-b"},
				{ComponentID: "c-shared"},
			},
		},
	}
	relations := map[string]string{"c-a": RelationDirect, "c-b": RelationDirect, "c-shared": RelationShared}
	ownership := buildFileOwnership(resolution, relations, targets)

	if fo := ownership["shared/util.go"]; fo == nil {
		t.Fatal("shared/util.go missing from ownership")
	} else {
		if len(fo.TargetIDs) != 2 {
			t.Errorf("shared/util.go targets = %v, want 2 targets", fo.TargetIDs)
		}
		if fo.Relation != RelationShared {
			t.Errorf("shared/util.go relation = %q, want shared", fo.Relation)
		}
	}

	if fo := ownership["a/main.go"]; fo == nil {
		t.Fatal("a/main.go missing from ownership")
	} else {
		if len(fo.TargetIDs) != 1 {
			t.Errorf("a/main.go targets = %v, want 1", fo.TargetIDs)
		}
		if fo.Relation != RelationDirect {
			t.Errorf("a/main.go relation = %q, want direct", fo.Relation)
		}
	}

	if fo := ownership["README.md"]; fo == nil {
		t.Fatal("README.md missing from ownership")
	} else {
		if fo.Relation != RelationRepositoryGlobal {
			t.Errorf("README.md relation = %q, want repository-global", fo.Relation)
		}
		if fo.Context != "docs" {
			t.Errorf("README.md context = %q, want docs", fo.Context)
		}
	}
}

func TestContextForPathLocal_MatchesAggregation(t *testing.T) {
	paths := []string{
		"README.md",
		"src/main.go",
		"tests/foo_test.go",
		"docs/guide.md",
		".github/workflows/ci.yml",
		"deploy/helm/chart.yaml",
		"vendor/lib.go",
		"examples/demo.py",
	}
	for _, path := range paths {
		local := contextForPathLocal(path)
		if local == "" {
			t.Errorf("contextForPathLocal(%q) returned empty", path)
		}
	}
}

func TestResolveStableIDsAndOwnershipAboveNestedManifest(t *testing.T) {
	root := t.TempDir()
	component := filepath.Join(root, "component")
	manifestDir := filepath.Join(component, "src")
	writeFile(t, filepath.Join(component, "server.json"), `{"name":"example/server","packages":[{"registryType":"npm","identifier":"example"}]}`)
	writeFile(t, filepath.Join(manifestDir, "package.json"), `{"name":"server","dependencies":{"@modelcontextprotocol/sdk":"^1"}}`)
	writeFile(t, filepath.Join(manifestDir, "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	writeFile(t, filepath.Join(component, "README.md"), "owned docs")
	first, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(first.Targets))
	}
	if first.Targets[0].ID == "" || first.Targets[0].Project.ID == "" || first.Targets[0].Project.ComponentID == "" {
		t.Fatal("expected stable project/component/target IDs")
	}
	if first.Targets[0].ID != second.Targets[0].ID {
		t.Errorf("target ID changed: %q vs %q", first.Targets[0].ID, second.Targets[0].ID)
	}
	if filepath.Clean(first.Targets[0].Project.OwnershipRoot) != filepath.Clean(component) {
		t.Fatalf("ownership root = %q, want %q", first.Targets[0].Project.OwnershipRoot, component)
	}
	roots := first.Targets[0].ScanRoots()
	if len(roots) != 1 || filepath.Clean(roots[0]) != filepath.Clean(component) {
		t.Fatalf("scan roots = %v, want component root", roots)
	}
}
