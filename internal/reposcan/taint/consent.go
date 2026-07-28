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
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".venv": true,
	"venv": true, "vendor": true, "dist": true, "build": true,
}

// DetectLangs returns the source languages present in repoPath.
func DetectLangs(repoPath string) []string {
	found := map[string]bool{}
	_ = filepath.WalkDir(repoPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
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
// (go:generate, cgo), so it is off unless the caller explicitly opts in with
// --codeql-allow-build.
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
			"execute build-time code (go:generate, cgo); skipped. Pass --codeql-allow-build " +
			"to enable it on code you trust.")
	}
	return false
}
