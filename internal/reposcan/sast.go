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
		// Warn but continue when an ENTRY can't be walked or statted (e.g. permission
		// denied): one bad path must not abort the scan, but the skip is surfaced so
		// reduced coverage is not silent. The scan ROOT is different: if it cannot be
		// read there is nothing to scan, and continuing would report a missing or
		// unreadable repo as a clean zero-finding result with a valid SARIF and exit 0.
		if err != nil {
			if filePath == s.repoPath {
				return fmt.Errorf("cannot read scan root %s: %w", filePath, err)
			}
			fmt.Fprintf(os.Stderr, "reposcan: skipping %s: %v\n", filePath, err)
			return nil
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

		// Skip non-regular files (FIFOs, sockets, devices, symlinks). Reading a FIFO blocks
		// forever and a socket/device errors; one such file must not hang or crash the scan.
		if !info.Mode().IsRegular() {
			return nil
		}

		// Skip files larger than configured max size
		if info.Size() > s.config.MaxFileSize {
			return nil
		}

		// Read file content
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			// Surface the skip so an unreadable file reduces coverage loudly, not silently.
			fmt.Fprintf(os.Stderr, "reposcan: skipping unreadable %s: %v\n", filePath, err)
			return nil
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

// runTaintEngine runs every installed source->sink taint engine and merges their paths.
// Engines activate by installation: OpenGrep (fast, intra-file) and CodeQL (deep,
// cross-file) each run when their pinned binary is resolvable and degrade quietly
// otherwise, so there is no engine flag at all -- installing an engine is what enables it.
// Neither engine aborts the scan on failure: OpenGrep discards its results and reports
// the error, while CodeQL keeps whatever paths the languages that succeeded produced and
// reports the ones that failed.
func (s *SASTScanner) runTaintEngine(ctx context.Context) []*proto.Finding {
	var paths []taint.PathRecord

	// OpenGrep: fast intra-file Python taint.
	ocfg := taint.DefaultConfig()
	ocfg.Excludes = s.config.ExcludedPaths // honor the same exclusions as SCA/secrets/YARA
	if s.config.MaxFileSize > 0 {
		// Honor the user's --max-file-size for taint too (every other scanner respects it)
		// instead of only the engine's own default. Clamp so the int64->int narrowing can
		// never wrap to a small or negative byte cap on a 32-bit build.
		maxBytes := s.config.MaxFileSize
		if maxBytes > math.MaxInt {
			maxBytes = math.MaxInt
		}
		ocfg.MaxTargetBytes = int(maxBytes)
	}
	if eng := taint.NewEngine(ocfg); eng.Available() {
		if p, err := eng.Scan(ctx, s.repoPath); err != nil {
			fmt.Printf("SAST opengrep error (skipping): %v\n", err)
		} else {
			fmt.Printf("SAST opengrep found %d taint paths\n", len(p))
			paths = append(paths, p...)
		}
	} else {
		// Names the engine, not "taint analysis": the CodeQL pass below may still run, and
		// claiming taint was skipped while reporting CodeQL paths reads as a contradiction.
		fmt.Println("SAST opengrep engine not found; skipping the fast intra-file pass " +
			"(run `make install-opengrep` or set MCPXRAY_OPENGREP_BIN)")
	}

	// CodeQL: the deep cross-file/interprocedural pass (slower; builds a DB per language).
	ccfg := taint.DefaultCodeQLConfig() // resolves the bin+packs once (Stat/Executable)
	if !taint.NewCodeQLEngine(ccfg).Available() {
		fmt.Println("SAST codeql engine not available (needs the codeql binary and query packs); " +
			"skipping (run `make install-codeql`, or set MCPXRAY_CODEQL_BIN / MCPXRAY_CODEQL_PACKS)")
	} else {
		// Pass exclusions into DETECTION, not just result-filtering: a language living only
		// in an excluded dir must not trigger the Go consent warning, and must not be
		// extracted/compiled by `database create` under --codeql-allow-build.
		langs := taint.DetectLangs(s.repoPath, s.config.ShouldExclude)
		ccfg.AllowGoBuild = taint.ResolveGoBuildConsent(langs, s.config.CodeQLAllowBuild)
		// Keep any partial results, but surface an analysis failure loudly instead of
		// letting a broken CodeQL run read as a clean "found 0 taint paths".
		p, err := taint.NewCodeQLEngine(ccfg).Scan(ctx, s.repoPath, langs)
		p = s.dropExcludedPaths(p) // CodeQL has no engine-side exclude; honor it here
		paths = append(paths, p...)
		// Report the failure FIRST so a partial result is never read as a complete one,
		// then always report a count -- a genuine clean run must be visibly distinct from
		// the engine never having run.
		if err != nil {
			fmt.Printf("SAST codeql analysis failed (results may be incomplete): %v\n", err)
		}
		fmt.Printf("SAST codeql found %d taint paths\n", len(p))
	}

	return taint.PathsToFindings(taint.MergePaths(paths))
}

// dropExcludedPaths removes taint paths whose sink or source file is under a configured
// excluded path, so CodeQL honors the same exclusions as opengrep/SCA/secrets (its
// extraction has no engine-side exclude, so its results are filtered here).
func (s *SASTScanner) dropExcludedPaths(paths []taint.PathRecord) []taint.PathRecord {
	out := paths[:0]
	for _, p := range paths {
		if s.config.ShouldExclude(p.SinkFile) || s.config.ShouldExclude(p.SourceFile) {
			continue
		}
		out = append(out, p)
	}
	return out
}
