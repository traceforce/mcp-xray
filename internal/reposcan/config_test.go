package reposcan

import "testing"

// TestShouldExcludeScopedToRoot locks the fix for the silent-empty-scan bug: an exclude
// pattern must match a directory or file INSIDE the scanned repo, never an ancestor of
// the scan root. A repo checked out under /tmp (or build/, out/, ...) must still be
// scanned, while in-repo junk directories are still excluded.
func TestShouldExcludeScopedToRoot(t *testing.T) {
	cfg := &Config{Root: "/tmp/mcp-demo", ExcludedPaths: DefaultConfig().ExcludedPaths}

	// Ancestor segments ("tmp") must NOT exclude files inside the repo.
	for _, in := range []string{"/tmp/mcp-demo/server.py", "/tmp/mcp-demo/pkg/handler.py"} {
		if cfg.ShouldExclude(in) {
			t.Errorf("ancestor segment must not exclude %q", in)
		}
	}
	// The scan root itself is never excluded.
	if cfg.ShouldExclude("/tmp/mcp-demo") {
		t.Error("scan root must not be excluded")
	}
	// In-repo junk directories / patterns must STILL be excluded.
	for _, in := range []string{
		"/tmp/mcp-demo/node_modules/x.js",
		"/tmp/mcp-demo/.venv/lib/y.py",
		"/tmp/mcp-demo/build/z.o",
		"/tmp/mcp-demo/pkg.egg-info/PKG-INFO",
	} {
		if !cfg.ShouldExclude(in) {
			t.Errorf("in-repo exclude must still fire for %q", in)
		}
	}
}

// TestShouldExcludeRelativeRoot covers `repo-scan .`, where Walk yields root-relative paths.
func TestShouldExcludeRelativeRoot(t *testing.T) {
	cfg := &Config{Root: ".", ExcludedPaths: DefaultConfig().ExcludedPaths}
	if cfg.ShouldExclude("server.py") {
		t.Error("top-level file must not be excluded under a relative root")
	}
	if !cfg.ShouldExclude("node_modules/dep/index.js") {
		t.Error("in-repo node_modules must be excluded under a relative root")
	}

	// `repo-scan build`: the root dir is itself named like an exclude pattern, and it is
	// an ancestor of every walked path -- its own name must not exclude the scan.
	buildRoot := &Config{Root: "build", ExcludedPaths: DefaultConfig().ExcludedPaths}
	if buildRoot.ShouldExclude("build/server.py") {
		t.Error("a root named `build` must not exclude its own files")
	}
	if !buildRoot.ShouldExclude("build/node_modules/x.js") {
		t.Error("in-repo node_modules must still be excluded under root `build`")
	}
}

// TestShouldExcludeLegacyWithoutRoot proves an empty Root keeps the old whole-path
// behavior, so any caller that does not set Root is unaffected by the change.
func TestShouldExcludeLegacyWithoutRoot(t *testing.T) {
	cfg := &Config{ExcludedPaths: []string{"tmp", "node_modules"}}
	if !cfg.ShouldExclude("/tmp/demo/server.py") {
		t.Error("without Root, legacy ancestor matching must be preserved")
	}
	if !cfg.ShouldExclude("/repo/node_modules/x.js") {
		t.Error("without Root, an in-repo match must still work")
	}
}

// TestShouldExcludeExcludedDirs covers the ExcludedDirs field: full relative
// directory paths excluded by prefix match, used by the repo-level scan to
// skip all project directories without the false-positive risk of segment-
// based matching (e.g. a project named "api" should not exclude unrelated
// paths that happen to contain an "api" segment).
func TestShouldExcludeExcludedDirs(t *testing.T) {
	cfg := &Config{
		Root:         "/repo",
		ExcludedDirs: []string{"servers/server-a", "packages/shared"},
	}

	// Files inside an excluded directory are excluded.
	for _, path := range []string{
		"/repo/servers/server-a/main.go",
		"/repo/servers/server-a/src/handler.py",
		"/repo/packages/shared/util.js",
	} {
		if !cfg.ShouldExclude(path) {
			t.Errorf("expected %q to be excluded by ExcludedDirs", path)
		}
	}

	// The excluded directory itself is excluded.
	if !cfg.ShouldExclude("/repo/servers/server-a") {
		t.Error("the excluded directory entry itself must be excluded")
	}

	// Files NOT inside an excluded directory are NOT excluded.
	for _, path := range []string{
		"/repo/Dockerfile",
		"/repo/.github/workflows/ci.yml",
		"/repo/scripts/deploy.sh",
		"/repo/servers/server-b/main.go",
	} {
		if cfg.ShouldExclude(path) {
			t.Errorf("expected %q to NOT be excluded by ExcludedDirs", path)
		}
	}

	// An ExcludedDirs entry of "." is silently ignored (the scan root itself
	// is never excluded, matching the existing ExcludedPaths behavior).
	dotCfg := &Config{Root: "/repo", ExcludedDirs: []string{"."}}
	if dotCfg.ShouldExclude("/repo/server.py") {
		t.Error("ExcludedDirs entry '.' must not exclude files at the scan root")
	}
}

// TestShouldExcludeExcludedDirsAndPathsCoexist proves that ExcludedDirs and
// ExcludedPaths fire independently — a path excluded by either is excluded.
func TestShouldExcludeExcludedDirsAndPathsCoexist(t *testing.T) {
	cfg := &Config{
		Root:          "/repo",
		ExcludedPaths: []string{"node_modules"},
		ExcludedDirs:  []string{"servers/server-a"},
	}
	if !cfg.ShouldExclude("/repo/servers/server-a/main.go") {
		t.Error("ExcludedDirs should fire")
	}
	if !cfg.ShouldExclude("/repo/scripts/node_modules/dep.js") {
		t.Error("ExcludedPaths should fire even when ExcludedDirs is set")
	}
	if cfg.ShouldExclude("/repo/scripts/deploy.sh") {
		t.Error("file matching neither ExcludedDirs nor ExcludedPaths should not be excluded")
	}
}
