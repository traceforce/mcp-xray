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
	// Root is the scan root. Exclude patterns are matched only against path segments
	// BELOW it, so the name of a directory ABOVE the repo (a checkout under /tmp or
	// ~/build) can never exclude the whole scan. Empty keeps the legacy whole-path
	// behavior.
	Root string
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
