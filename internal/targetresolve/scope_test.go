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

func TestProjectScanRoot(t *testing.T) {
	if got := (&Project{Dir: "/repo/server/"}).ScanRoot(); got != filepath.Clean("/repo/server") {
		t.Errorf("ScanRoot() without an ownership root = %q, want the project directory", got)
	}
	if got := (&Project{Dir: "/repo/server/src", OwnershipRoot: "/repo/server/"}).ScanRoot(); got != filepath.Clean("/repo/server") {
		t.Errorf("ScanRoot() = %q, want the ownership root", got)
	}
}

// dependencyFilesOf is the dependency files of a target whose one project
// is rooted at root.
func dependencyFilesOf(root string, allProjects ...*Project) []string {
	project := &Project{ID: "p", Dir: root, OwnershipRoot: root}
	return (&Target{Project: project, Included: []*Project{project}}).DependencyFiles(append(allProjects, project))
}

func TestDependencyFiles_FindsKnownManifestsAndLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "x"}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{}`)
	writeFile(t, filepath.Join(root, "README.md"), "not a manifest")

	found := dependencyFilesOf(root)
	if len(found) != 2 {
		t.Fatalf("expected 2 manifest/lockfile matches (README.md excluded), got %d: %v", len(found), found)
	}
}

func TestDependencyFiles_PrunesDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "some-dep", "package.json"), `{"name": "dep"}`)
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "x"}`)

	found := dependencyFilesOf(root)
	if len(found) != 1 {
		t.Fatalf("expected node_modules to be pruned by the default excludes, leaving 1 manifest, got %d: %v", len(found), found)
	}
}

// A discovered project nested in the target's directory that the target
// does not include is left out of its scan, so its dependency files are not
// listed as the target's.
func TestDependencyFiles_LeavesOutNestedProjectsTheTargetExcludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n")
	writeFile(t, filepath.Join(root, "tools", "helper", "package.json"), `{"name": "helper"}`)
	writeFile(t, filepath.Join(root, "tools", "helper", "package-lock.json"), `{}`)
	helperDir := filepath.Join(root, "tools", "helper")
	helper := &Project{ID: "p-helper", Dir: helperDir, OwnershipRoot: helperDir}

	found := dependencyFilesOf(root, helper)
	if len(found) != 1 || found[0] != filepath.Join(root, "go.mod") {
		t.Errorf("DependencyFiles = %v, want only the target's own go.mod", found)
	}
}

func TestDependencyFiles_NoScanRootsFindsNothing(t *testing.T) {
	if found := (&Target{}).DependencyFiles(nil); len(found) != 0 {
		t.Errorf("expected no roots to find nothing, got %v", found)
	}
}

func TestResidualExcludes(t *testing.T) {
	root := t.TempDir()
	roots := []string{
		filepath.Join(root, "servers", "server-b"),
		filepath.Join(root, "packages", "shared"),
		filepath.Join(root, "servers", "server-b"), // duplicate
		root,               // the repository itself is never excluded
		filepath.Dir(root), // nor is anything outside it
	}
	got := residualExcludes(root, roots)
	want := []string{"packages/shared", "servers/server-b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("residualExcludes = %v, want %v", got, want)
	}
}
