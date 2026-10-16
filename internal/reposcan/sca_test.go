package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) failed: %v", path, err)
	}
}

func TestSplitScanRoots_NoExclusionsReturnsSingleRecursiveRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "a"))
	mustMkdirAll(t, filepath.Join(root, "b"))

	recursive, shallow := splitScanRoots(root, &Config{Root: root})
	if len(shallow) != 0 {
		t.Errorf("expected no shallow roots when nothing is excluded, got %v", shallow)
	}
	if len(recursive) != 1 || recursive[0] != root {
		t.Errorf("expected exactly [%q] as the sole recursive root, got %v", root, recursive)
	}
}

func TestSplitScanRoots_FullyExcludedRootReturnsNothing(t *testing.T) {
	root := t.TempDir()
	// An ExcludedDirs entry of "." is a no-op per Config.ShouldExclude (the
	// scan root itself is never excluded), so exclude the whole tree via an
	// ExcludedPaths segment match on the root's own basename instead, with
	// Root set one level up so that segment is actually below Root.
	cfg := &Config{Root: filepath.Dir(root), ExcludedPaths: []string{filepath.Base(root)}}

	recursive, shallow := splitScanRoots(root, cfg)
	if len(recursive) != 0 || len(shallow) != 0 {
		t.Errorf("expected no roots at all when the root itself is excluded, got recursive=%v shallow=%v", recursive, shallow)
	}
}

func TestSplitScanRoots_ExcludedChildProducesShallowRootPlusCleanSiblings(t *testing.T) {
	root := t.TempDir()
	excluded := filepath.Join(root, "tools", "other")
	clean := filepath.Join(root, "src")
	mustMkdirAll(t, excluded)
	mustMkdirAll(t, clean)
	mustMkdirAll(t, filepath.Join(root, "tools")) // parent of the excluded child

	cfg := &Config{Root: root, ExcludedDirs: []string{"tools/other"}}
	recursive, shallow := splitScanRoots(root, cfg)

	// root has an excluded descendant, so root itself must be a shallow
	// root (its own direct files scanned non-recursively) rather than a
	// recursive one (which would pull tools/other back in).
	if !contains(shallow, root) {
		t.Errorf("expected root %q to be a shallow root, got shallow=%v", root, shallow)
	}
	// "tools" is not itself excluded, but its only child is, so it must
	// also be a shallow root: its own direct files (if it had any -- this
	// fixture has none, but the algorithm can't assume that in general)
	// still need to be scanned, just not recursively (that would pull
	// tools/other back in).
	tools := filepath.Join(root, "tools")
	if !contains(shallow, tools) {
		t.Errorf("expected %q (parent of the excluded dir) to be a shallow root, got shallow=%v", tools, shallow)
	}
	// src has no exclusion anywhere inside it, so it's a clean recursive root.
	if !contains(recursive, clean) {
		t.Errorf("expected clean sibling %q to be a recursive root, got recursive=%v", clean, recursive)
	}
	// The excluded directory must never appear in either list.
	if contains(recursive, excluded) || contains(shallow, excluded) {
		t.Errorf("excluded directory %q must not appear in either list: recursive=%v shallow=%v", excluded, recursive, shallow)
	}
}

func TestSplitScanRoots_NestedExclusionTwoLevelsDeepIsPruned(t *testing.T) {
	root := t.TempDir()
	// root
	//   packages/            <- has an excluded child two levels down
	//     good/               <- clean, should end up recursive
	//     bad/
	//       vendored/         <- excluded
	deepExcluded := filepath.Join(root, "packages", "bad", "vendored")
	good := filepath.Join(root, "packages", "good")
	mustMkdirAll(t, deepExcluded)
	mustMkdirAll(t, good)

	cfg := &Config{Root: root, ExcludedDirs: []string{"packages/bad/vendored"}}
	recursive, shallow := splitScanRoots(root, cfg)

	bad := filepath.Join(root, "packages", "bad")
	if !contains(shallow, bad) {
		t.Errorf("expected %q (parent of the excluded dir) to be a shallow root, got shallow=%v", bad, shallow)
	}
	if !contains(shallow, root) {
		t.Errorf("expected root %q to be a shallow root (exclusion exists somewhere beneath it), got shallow=%v", root, shallow)
	}
	if !contains(recursive, good) {
		t.Errorf("expected clean subtree %q to be a recursive root, got recursive=%v", good, recursive)
	}
	if contains(recursive, deepExcluded) || contains(shallow, deepExcluded) {
		t.Errorf("deeply nested excluded dir %q must not appear anywhere: recursive=%v shallow=%v", deepExcluded, recursive, shallow)
	}
}

func TestSplitScanRoots_UnreadableRootFallsBackToSingleEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	recursive, shallow := splitScanRoots(root, &Config{Root: root})
	if len(shallow) != 0 || len(recursive) != 1 || recursive[0] != root {
		t.Errorf("expected an unreadable root to fall back to a single recursive entry (letting osv-scanner's own os.Stat report the real error), got recursive=%v shallow=%v", recursive, shallow)
	}
}

// A target scan's unit leaves out only other targets' trees: the default
// excludes (build, cache, vendor, ...) never pruned the full-repository
// dependency scan, so pruning them here would lose lockfiles a plain scan
// reports.
func TestUnitScanRoots_LeavesOutOnlyExcludedDirs(t *testing.T) {
	root := t.TempDir()
	build := filepath.Join(root, "build")
	cache := filepath.Join(root, "tools", "cache")
	other := filepath.Join(root, "other")
	for _, dir := range []string{build, cache, other} {
		mustMkdirAll(t, dir)
	}
	cfg := DefaultConfig()
	cfg.Root = root
	cfg.ExcludedPaths = append(cfg.ExcludedPaths, "tools")
	cfg.ExcludedDirs = []string{"other"}

	recursive, shallow := NewSCAScanner(root, cfg).unitScanRoots()

	tools := filepath.Join(root, "tools")
	if !contains(recursive, build) || !contains(recursive, tools) {
		t.Errorf("recursive roots = %v, want %q and %q despite ExcludedPaths", recursive, build, tools)
	}
	if contains(recursive, other) || contains(shallow, other) {
		t.Errorf("excluded dir %q was scanned: recursive=%v shallow=%v", other, recursive, shallow)
	}
	if !contains(shallow, root) {
		t.Errorf("shallow roots = %v, want the root %q for its own files", shallow, root)
	}
}

// A full-repository dependency scan with nothing to scan reports zero
// vulnerabilities, not an error.
func TestSCAScan_NoDependencyFilesFindsNothing(t *testing.T) {
	root := t.TempDir()
	findings, err := NewSCAScanner(root, &Config{Root: root}).Scan(context.Background())
	if err != nil || len(findings) != 0 {
		t.Errorf("Scan() = %v, %v; want no findings and no error", findings, err)
	}
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// TestScanRootOwnFiles_EmptyDirReportsUnsupported confirms ScanRootOwnFiles
// (the workspace-root dependency fallback's entry point) reports
// ErrUnsupportedInput -- not a hard error -- for a directory with nothing
// osv-scanner can extract package information from. This runs fast and
// network-free: an empty directory has zero files to extract from, so
// osv-scanner never reaches a vulnerability-database lookup.
func TestScanRootOwnFiles_EmptyDirReportsUnsupported(t *testing.T) {
	root := t.TempDir()
	findings, err := ScanRootOwnFiles(root)
	if len(findings) != 0 {
		t.Errorf("expected no findings from an empty directory, got %v", findings)
	}
	if !IsUnsupportedScanError(err) {
		t.Errorf("expected an unsupported-input error for an empty directory, got %v", err)
	}
}

func TestIsUnsupportedOSVInput(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"no packages found", errUnsupportedTestError("scan failed: No packages found in scan"), true},
		{"case insensitive", errUnsupportedTestError("NO PACKAGES FOUND IN SCAN"), true},
		{"unrelated error", errUnsupportedTestError("permission denied"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnsupportedOSVInput(tc.err); got != tc.want {
				t.Errorf("isUnsupportedOSVInput(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type errUnsupportedTestError string

func (e errUnsupportedTestError) Error() string { return string(e) }
