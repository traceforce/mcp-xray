package targetresolve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// detectSubmoduleWarnings looks for a .gitmodules file at the repo root and
// flags any declared submodule whose working directory is missing or empty
// -- the standard signature of `git clone` without
// `git submodule update --init`, which silently leaves that part of the
// repository (and, worse, any MCP server or shared component inside it)
// unscanned rather than erroring. This detects uninitialized submodules; it
// does not attempt to initialize them, and it does not separately search for
// nested repositories that are not declared as submodules at all (a fully
// independent nested .git tree elsewhere in the repo) -- that broader case
// from pattern 6 is left for a follow-up.
func detectSubmoduleWarnings(repoRoot string) []string {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".gitmodules"))
	if err != nil {
		return nil
	}

	var warnings []string
	for _, subPath := range parseGitmodulesPaths(data) {
		fullPath := filepath.Join(repoRoot, subPath)
		entries, err := os.ReadDir(fullPath)
		switch {
		case err != nil && os.IsNotExist(err):
			warnings = append(warnings, fmt.Sprintf(
				"submodule %q is declared in .gitmodules but its directory does not exist; run `git submodule update --init` before scanning, or its contents will be missing from analysis", subPath))
		case err == nil && len(entries) == 0:
			warnings = append(warnings, fmt.Sprintf(
				"submodule %q exists but is empty (not initialized via `git submodule update --init`); its contents will not be scanned", subPath))
		}
	}
	return warnings
}

// parseGitmodulesPaths extracts every "path = ..." value from a .gitmodules
// file. This is a minimal line-oriented reader rather than a full git-config
// parser: .gitmodules only ever needs its "path" values here, and every
// real-world .gitmodules file uses the simple "key = value" form this covers.
func parseGitmodulesPaths(data []byte) []string {
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "path") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "path"))
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		if value := strings.TrimSpace(strings.TrimPrefix(rest, "=")); value != "" {
			paths = append(paths, value)
		}
	}
	return paths
}
