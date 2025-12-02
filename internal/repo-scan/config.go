package reposcan

import (
	"path/filepath"
	"strings"
)

// Config holds configuration for repository scanning
type Config struct {
	// MaxFileSize is the maximum file size in bytes to scan
	MaxFileSize int64
	// ExcludePatterns are directory patterns to exclude from scanning
	// These are matched against path segments (e.g., ".venv", "node_modules", "cache")
	ExcludePatterns []string
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxFileSize: 1 * 1024 * 1024, // 1MB
		ExcludePatterns: []string{
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
			".env",
			".env.local",
			".env.*.local",
		},
	}
}

// ShouldExclude checks if a file path should be excluded based on the config
func (c *Config) ShouldExclude(filePath string) bool {
	// Normalize path separators
	normalizedPath := filepath.ToSlash(filepath.Clean(filePath))
	pathParts := strings.Split(normalizedPath, "/")

	// Check each path segment against exclude patterns
	for _, part := range pathParts {
		// Skip empty parts
		if part == "" || part == "." {
			continue
		}

		// Check if this part matches any exclude pattern
		for _, pattern := range c.ExcludePatterns {
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
