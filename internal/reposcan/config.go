package reposcan

import (
	"path/filepath"
	"strings"
)

// Config holds configuration for repository scanning
type Config struct {
	// MaxFileSize is the maximum file size in bytes to scan
	MaxFileSize int64
	// ExcludedPaths are path-segment patterns (files or directories) to exclude from
	// scanning (e.g., ".venv", "node_modules", "cache").
	ExcludedPaths []string
	// ExcludedDirs are relative directory paths (relative to Root) excluded by
	// prefix match. Unlike ExcludedPaths (which matches individual path
	// segments), these match the full relative path from Root, so
	// "servers/server-b" excludes only that specific subtree without
	// affecting unrelated paths that happen to contain a "servers" segment.
	ExcludedDirs []string
	// Root is the scan root. Exclude patterns are matched only against path segments
	// BELOW it, so the name of a directory ABOVE the repo (a checkout under /tmp or
	// ~/build) can never exclude the whole scan. Empty keeps the legacy whole-path
	// behavior.
	Root string
	// CodeQLAllowBuild grants consent to compile Go targets during CodeQL analysis.
	CodeQLAllowBuild bool
	// CodeQLTimeoutSec overrides the per-language CodeQL budget (create + analyze), in
	// seconds. Zero means the caller said nothing: fall back to MCPXRAY_CODEQL_TIMEOUT,
	// then to codeqlDefaultTimeoutSec. A large target legitimately exceeds the default
	// (reported as "timed out after Ns"), so the budget must be raisable without
	// recompiling.
	CodeQLTimeoutSec int
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		ExcludedPaths: []string{
			".venv",
			"venv",
			"__pycache__",
			".pytest_cache",
			"node_modules",
			".node_modules",
			"vendor",
			"target",
			"dist",
			"build",
			".build",
			"out",
			".out",
			"cache",
			".cache",
			"tmp",
			".tmp",
			"temp",
			".temp",
			".git",
			".svn",
			".hg",
			".bzr",
			".idea",
			".vscode",
			".vs",
			".gradle",
			".mvn",
			"bin",
			"obj",
			".next",
			".nuxt",
			".turbo",
			".yarn",
			"coverage",
			".coverage",
			".nyc_output",
			"*.egg-info",
			".eggs",
			".tox",
			"go.sum",
			"package-lock.json",
			"yarn.lock",
			"pnpm-lock.yaml",
			"pnpm-lock.yaml",
		},
	}
}

// ShouldExclude checks if a file path should be excluded based on the config.
// Matching is scoped to the part of the path BELOW Root: an exclude pattern must name
// a directory or file inside the scanned repo. Without this, a repo checked out under
// e.g. /tmp or ~/build matched the ancestor segment ("tmp", "build") and the entire
// walk was skipped silently.
func (c *Config) ShouldExclude(filePath string) bool {
	// Scope to the repo: compare only the segments below the scan root. A path outside
	// Root (rel starts with "..") falls back to whole-path matching rather than silently
	// un-excluding it.
	scoped := filePath
	if c.Root != "" {
		if rel, err := filepath.Rel(c.Root, filePath); err == nil &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			scoped = rel
		}
	}

	// Normalize path separators
	normalizedPath := filepath.ToSlash(filepath.Clean(scoped))
	if normalizedPath == "." {
		return false // the scan root itself is never excluded
	}

	// Directory-path exclusions: prefix match on the full relative path.
	for _, dir := range c.ExcludedDirs {
		normDir := filepath.ToSlash(filepath.Clean(dir))
		if normDir == "." {
			continue
		}
		if normalizedPath == normDir || strings.HasPrefix(normalizedPath, normDir+"/") {
			return true
		}
	}

	pathParts := strings.Split(normalizedPath, "/")

	// Check each path segment against exclude patterns
	for _, part := range pathParts {
		// Skip empty parts
		if part == "" || part == "." {
			continue
		}

		// Check if this part matches any exclude pattern
		for _, pattern := range c.ExcludedPaths {
			// Wildcard matching for patterns like "*.egg-info" or ".env.*.local"
			if strings.Contains(pattern, "*") {
				if matched, _ := filepath.Match(pattern, part); matched {
					return true
				}
			} else {
				// Exact match for patterns without wildcards
				if part == pattern {
					return true
				}
			}
		}
	}

	return false
}
