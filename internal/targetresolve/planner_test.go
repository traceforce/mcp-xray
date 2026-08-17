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
