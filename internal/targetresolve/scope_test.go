package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestScanRoots_DedupesAndDropsNestedRoots(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "server")
	nested := filepath.Join(root, "server", "internal", "shared")
	sibling := filepath.Join(root, "shared-lib")

	target := &Target{
		Project: &Project{Dir: parent},
		Included: []*Project{
			{Dir: parent},
			{Dir: nested}, // nested inside parent -- must be dropped
			{Dir: sibling},
			{Dir: sibling}, // duplicate -- must be deduped
		},
	}

	roots := target.ScanRoots()
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots (parent + sibling), got %d: %v", len(roots), roots)
	}
	found := map[string]bool{}
	for _, r := range roots {
		found[r] = true
	}
	if !found[filepath.Clean(parent)] || !found[filepath.Clean(sibling)] {
		t.Errorf("expected roots to contain parent and sibling, got %v", roots)
	}
	if found[filepath.Clean(nested)] {
		t.Errorf("nested root %q should have been dropped", nested)
	}
}

func TestPrimaryRoot(t *testing.T) {
	target := &Target{Project: &Project{Dir: "/repo/server/"}}
	if got := target.PrimaryRoot(); got != filepath.Clean("/repo/server/") {
		t.Errorf("PrimaryRoot() = %q, want %q", got, filepath.Clean("/repo/server/"))
	}
}

func TestDiscoveredManifests_FindsKnownManifestsAndLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "x"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{}`)
	writeFile(t, filepath.Join(root, "README.md"), "not a manifest")

	found := DiscoveredManifests([]string{root})
	if len(found) != 2 {
		t.Fatalf("expected 2 manifest/lockfile matches (README.md excluded), got %d: %v", len(found), found)
	}
}

func TestDiscoveredManifests_PrunesDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "some-dep", "package.json"), `{"name": "dep"}`)
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "x"}`)

	found := DiscoveredManifests([]string{root})
	if len(found) != 1 {
		t.Fatalf("expected node_modules to be pruned by the default excludes, leaving 1 manifest, got %d: %v", len(found), found)
	}
}

func TestDiscoveredManifests_DedupesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n")

	found := DiscoveredManifests([]string{root, root})
	if len(found) != 1 {
		t.Fatalf("expected exactly 1 result despite duplicate/overlapping roots, got %d: %v", len(found), found)
	}
}

func TestDiscoveredManifests_NoRootsFindsNothing(t *testing.T) {
	if found := DiscoveredManifests(nil); len(found) != 0 {
		t.Errorf("expected no roots to find nothing, got %v", found)
	}
}

func TestRepoLevelExcludes_ReturnsAllProjectDirsRelativeToRoot(t *testing.T) {
	root := t.TempDir()
	projects := []*Project{
		{Dir: filepath.Join(root, "servers", "server-a")},
		{Dir: filepath.Join(root, "servers", "server-b")},
		{Dir: filepath.Join(root, "packages", "shared")},
	}
	excludes := RepoLevelExcludes(root, projects)
	if len(excludes) != 3 {
		t.Fatalf("expected 3 excludes, got %d: %v", len(excludes), excludes)
	}
	want := map[string]bool{
		filepath.Join("packages", "shared"):   true,
		filepath.Join("servers", "server-a"):  true,
		filepath.Join("servers", "server-b"):  true,
	}
	for _, e := range excludes {
		if !want[e] {
			t.Errorf("unexpected exclude %q", e)
		}
	}
}

func TestRepoLevelExcludes_SkipsProjectAtRepoRoot(t *testing.T) {
	root := t.TempDir()
	projects := []*Project{
		{Dir: root},
	}
	excludes := RepoLevelExcludes(root, projects)
	if len(excludes) != 0 {
		t.Errorf("project at repo root should be skipped (rel='.'), got %v", excludes)
	}
}

func TestRepoLevelExcludes_DedupesIdenticalDirs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "server")
	projects := []*Project{
		{Dir: dir},
		{Dir: dir},
	}
	excludes := RepoLevelExcludes(root, projects)
	if len(excludes) != 1 {
		t.Fatalf("expected deduplication to 1, got %d: %v", len(excludes), excludes)
	}
}
