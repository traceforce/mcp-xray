package configscan

import (
	"os"
	"path/filepath"
)

var KnownMCPConfigs = []string{
	".cursor/mcp.json",
	"Library/Application Support/Claude/claude_desktop_config.json",
	".codeium/windsurf/mcp_config.json",
}

// ExpandConfigPath expands a config path relative to the home directory
// Paths starting with "." or "Library" are assumed to be relative to home directory
func ExpandConfigPath(path string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, path), nil
}

// GetAllKnownConfigPaths returns all known config paths expanded to full paths
func GetAllKnownConfigPaths() ([]string, error) {
	var expandedPaths []string
	for _, path := range KnownMCPConfigs {
		expanded, err := ExpandConfigPath(path)
		if err != nil {
			return nil, err
		}
		expandedPaths = append(expandedPaths, expanded)
	}
	return expandedPaths, nil
}
