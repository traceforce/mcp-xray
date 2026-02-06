package reposcan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/yararules"
	"mcpxray/proto"
)

type SASTScanner struct {
	repoPath string
	config   *Config
}

func NewSASTScanner(repoPath string, config *Config) *SASTScanner {
	return &SASTScanner{
		repoPath: repoPath,
		config:   config,
	}
}

// DetectUnsafeCommands analyzes content for unsafe system commands and returns matches with file/line info
func DetectUnsafeCommands(ctx context.Context, filePath string, content string) []yararules.UnsafeCommandMatch {
	// Normalize to catch obfuscation attempts
	lines := strings.Split(content, "\n")

	var matches []yararules.UnsafeCommandMatch
	seen := make(map[string]int) // Track pattern ID -> line number to avoid duplicates per file

	for lineNum, line := range lines {
		normalizedLine := yararules.NormalizeForPatternMatching(line)
		for _, pattern := range yararules.GetUnsafeSystemPatterns() {
			if pattern.Pattern.MatchString(normalizedLine) {
				// Check if we've already seen this pattern in this file
				key := pattern.Id
				if prevLine, exists := seen[key]; exists {
					// Only report if this is a different line (allow multiple instances)
					if prevLine == lineNum+1 {
						continue
					}
				}

				// Find the actual match in the original line
				match := pattern.Pattern.FindString(normalizedLine)
				if match == "" {
					match = pattern.Pattern.FindString(line)
				}
				if match == "" {
					match = "unsafe command detected"
				}

				matches = append(matches, yararules.UnsafeCommandMatch{
					PatternID: pattern.Id,
					Reason:    pattern.Reason,
					Severity:  pattern.Severity,
					File:      filePath,
					Line:      int32(lineNum + 1), // 1-indexed line numbers
					Match:     match,
				})
				seen[key] = lineNum + 1
			}
		}
	}

	return matches
}

// PopulateUnsafeCommands detects unsafe commands and populates the unsafe_commands_result field in proto.MCPServer
func (s *SASTScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	var allMatches []yararules.UnsafeCommandMatch

	err := filepath.Walk(s.repoPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if path should be excluded based on config
		if s.config.ShouldExclude(filePath) {
			// Skip entire directory if it matches exclude pattern
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Skip files larger than configured max size
		if info.Size() > s.config.MaxFileSize {
			return nil
		}

		// Read file content
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}

		// Detect unsafe commands in this file
		matches := DetectUnsafeCommands(ctx, filePath, string(fileContent))
		allMatches = append(allMatches, matches...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}

	fmt.Printf("SAST found %d unsafe commands\n", len(allMatches))
	// Convert matches to findings
	return yararules.ToFindings(allMatches), nil
}
