package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var langByExt = map[string]string{
	".py": "python", ".pyi": "python", ".go": "go",
	".ts": "typescript", ".tsx": "typescript", ".js": "typescript",
	".jsx": "typescript", ".mjs": "typescript", ".cjs": "typescript",
	// NodeNext explicit-module extensions. A repo whose only TS sources use these was
	// previously detected as having no languages at all and skipped entirely.
	".mts": "typescript", ".cts": "typescript",
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".venv": true,
	"venv": true, "vendor": true, "dist": true, "build": true,
}

// DetectLangs returns the source languages present in repoPath. exclude, if non-nil, is
// called with each entry's path RELATIVE to repoPath and reports whether to skip it.
//
// Pass Config.ShouldExclude so detection uses the SAME exclusion rule as result-filtering
// (dropExcludedPaths, which also feeds it root-relative paths) -- a single source of truth
// rather than a second matcher. This matters beyond tidiness: a language living only in an
// excluded dir would otherwise trigger the Go consent warning, and under
// --codeql-allow-build CodeQL's `database create` would extract and COMPILE code the user
// explicitly excluded (post-hoc result filtering is too late to stop a build). Pass nil to
// detect over the whole tree.
func DetectLangs(repoPath string, exclude func(string) bool) []string {
	found := map[string]bool{}
	_ = filepath.WalkDir(repoPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Match on the path RELATIVE to the repo root so an ancestor dir named like an
		// exclude pattern (a checkout under /tmp, ~/build) can't exclude the whole scan.
		if exclude != nil {
			if rel, relErr := filepath.Rel(repoPath, p); relErr == nil && rel != "." && exclude(rel) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if l, ok := langByExt[strings.ToLower(filepath.Ext(p))]; ok {
			found[l] = true
		}
		return nil
	})
	var out []string
	for _, l := range []string{"python", "typescript", "go"} {
		if found[l] {
			out = append(out, l)
		}
	}
	return out
}

// ResolveGoBuildConsent decides whether CodeQL may build a Go target. Building a Go
// database runs the Go toolchain over the target, which can EXECUTE build-time code
// (cgo compiles and runs C from the target), so it is off unless the caller explicitly
// opts in with --codeql-allow-build.
//
// It never prompts. Since the engines activate by installation, repo-scan reaches this
// on the default path for any repo containing Go; a y/N read on stdin would stall a
// piped or unattended scan mid-run. Without consent it warns and returns false, and the
// build-free Python/JS analysis still runs.
func ResolveGoBuildConsent(langs []string, allowFlag bool) bool {
	if allowFlag {
		return true
	}
	if slices.Contains(langs, "go") {
		fmt.Println("CodeQL Go analysis builds the target with the Go toolchain, which can " +
			"execute build-time code (cgo compiles and runs C from the target); skipped. Pass " +
			"--codeql-allow-build to enable it on code you trust.")
	}
	return false
}
