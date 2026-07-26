package reposcan

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan/taint"
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
	findings := yararules.ToFindings(allMatches)

	// Taint engine runs in addition to the YARA scan above. It degrades quietly when
	// the OpenGrep binary is absent, so existing YARA/SCA/secrets output is unaffected.
	findings = append(findings, s.runTaintEngine(ctx)...)
	return findings, nil
}

// runTaintEngine runs the OpenGrep source->sink taint engine. It activates by
// installation: it runs whenever the pinned engine is resolvable (MCPXRAY_OPENGREP_BIN
// or bin/opengrep next to the binary) and degrades quietly otherwise, so there is no
// engine flag to keep in sync. Any failure returns no findings rather than aborting.
func (s *SASTScanner) runTaintEngine(ctx context.Context) []*proto.Finding {
	cfg := taint.DefaultConfig()
	cfg.Excludes = s.config.ExcludedPaths // honor the same exclusions as SCA/secrets/YARA
	if s.config.MaxFileSize > 0 {
		// Honor the user's --max-file-size for taint too (every other scanner respects it)
		// instead of only the engine's own default. Clamp so the int64->int narrowing can
		// never wrap to a small or negative byte cap on a 32-bit build.
		maxBytes := s.config.MaxFileSize
		if maxBytes > math.MaxInt {
			maxBytes = math.MaxInt
		}
		cfg.MaxTargetBytes = int(maxBytes)
	}
	eng := taint.NewEngine(cfg)
	if !eng.Available() {
		fmt.Println("SAST taint engine (opengrep) not found; skipping taint analysis " +
			"(install opengrep or set MCPXRAY_OPENGREP_BIN)")
		return nil
	}
	paths, err := eng.Scan(ctx, s.repoPath)
	if err != nil {
		fmt.Printf("SAST taint engine error (skipping): %v\n", err)
		return nil
	}
	fmt.Printf("SAST taint engine found %d taint paths\n", len(paths))
	return taint.PathsToFindings(paths)
}
