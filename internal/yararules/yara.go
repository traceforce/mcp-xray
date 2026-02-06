package yararules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"mcpxray/proto"
)

// Reason represents standardized reasons for unsafe command detection
type Reason string

// Standardized reason categories for easier remediation mapping
const (
	ReasonDestructiveFileOps   Reason = "Destructive file operations"
	ReasonSystemSecurityBypass Reason = "System security bypass"
	ReasonSystemConfigChanges  Reason = "System configuration changes"
	ReasonRemoteCodeExecution  Reason = "Remote code execution"
	ReasonInsecureFilePerms    Reason = "Insecure file permissions"
	ReasonProcessManagement    Reason = "Process management"
	ReasonServiceManagement    Reason = "Service management"
	ReasonSystemControl        Reason = "System control"
	ReasonPackageInstallation  Reason = "Package installation"
	ReasonPrivilegeEscalation  Reason = "Privilege escalation"
	ReasonFileOwnershipChanges Reason = "File ownership changes"
	ReasonSystemAutomation     Reason = "System automation"
	ReasonCodeExecution        Reason = "Code execution"
)

// UnsafeCommandMatch represents a detected unsafe command pattern
type UnsafeCommandMatch struct {
	PatternID string             // Pattern ID that matched
	Reason    Reason             // Reason
	Severity  proto.RiskSeverity // Risk severity level (proto enum)
	File      string             // File path where the match was found
	Line      int32              // Line number where the match was found
	Match     string             // The actual matched text
}

// UnsafePattern represents a pattern that indicates unsafe system commands
type UnsafePattern struct {
	Id       string
	Pattern  *regexp.Regexp
	Reason   Reason
	Severity proto.RiskSeverity
}

// normalizeForPatternMatching normalizes command text to catch obfuscation attempts
func NormalizeForPatternMatching(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Normalize command separators to spaces to catch chained commands
	// Don't normalize | to preserve pipe detection for curl | bash patterns
	separators := []string{"&&", "||", ";", "\n", "\r", "\t"}
	for _, sep := range separators {
		text = strings.ReplaceAll(text, sep, " ")
	}

	// Normalize multiple spaces to single space
	for strings.Contains(text, "  ") {
		text = strings.ReplaceAll(text, "  ", " ")
	}

	return text
}

var (
	unsafeSystemPatterns     []UnsafePattern
	unsafeSystemPatternsOnce sync.Once
)

// loadUnsafeSystemPatterns loads patterns from the YARA file
func loadUnsafeSystemPatterns() {
	// Get the directory of this file
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	yaraFile := filepath.Join(dir, "unsafe_patterns.yar")

	data, err := os.ReadFile(yaraFile)
	if err != nil {
		panic(fmt.Sprintf("failed to load YARA patterns file: %v", err))
	}

	patterns, err := parseYaraFile(string(data))
	if err != nil {
		panic(fmt.Sprintf("failed to parse YARA patterns file: %v", err))
	}

	unsafeSystemPatterns = patterns
}

// getUnsafeSystemPatterns returns the loaded patterns, loading them if necessary
func GetUnsafeSystemPatterns() []UnsafePattern {
	unsafeSystemPatternsOnce.Do(loadUnsafeSystemPatterns)
	return unsafeSystemPatterns
}

// parseYaraFile parses a YARA file and extracts patterns
func parseYaraFile(content string) ([]UnsafePattern, error) {
	var patterns []UnsafePattern

	// Split into rule blocks
	ruleBlocks := extractRuleBlocks(content)

	for _, block := range ruleBlocks {
		pattern, err := parseRuleBlock(block)
		if err != nil {
			return nil, fmt.Errorf("error parsing rule: %w", err)
		}
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns, nil
}

// extractRuleBlocks extracts individual rule blocks from YARA file
func extractRuleBlocks(content string) []string {
	var blocks []string
	var currentBlock strings.Builder
	inRule := false
	braceCount := 0

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Check for rule start
		if strings.HasPrefix(trimmed, "rule ") {
			if inRule {
				// Save previous block
				blocks = append(blocks, currentBlock.String())
				currentBlock.Reset()
			}
			inRule = true
			braceCount = 0
		}

		if inRule {
			currentBlock.WriteString(line)
			currentBlock.WriteString("\n")

			// Count braces to detect rule end
			braceCount += strings.Count(line, "{")
			braceCount -= strings.Count(line, "}")

			if braceCount == 0 && strings.Contains(line, "}") {
				blocks = append(blocks, currentBlock.String())
				currentBlock.Reset()
				inRule = false
			}
		}
	}

	return blocks
}

// parseRuleBlock parses a single YARA rule block
func parseRuleBlock(block string) (*UnsafePattern, error) {
	lines := strings.Split(block, "\n")

	var id, reason, severityStr, patternStr string
	inMeta := false
	inStrings := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Detect sections
		if trimmed == "meta:" {
			inMeta = true
			inStrings = false
			continue
		}
		if trimmed == "strings:" {
			inMeta = false
			inStrings = true
			continue
		}
		if trimmed == "condition:" {
			inMeta = false
			inStrings = false
			continue
		}

		// Parse meta section
		if inMeta {
			if strings.HasPrefix(trimmed, "id = ") {
				id = extractQuotedValue(trimmed)
			} else if strings.HasPrefix(trimmed, "reason = ") {
				reason = extractQuotedValue(trimmed)
			} else if strings.HasPrefix(trimmed, "severity = ") {
				severityStr = extractQuotedValue(trimmed)
			}
		}

		// Parse strings section
		if inStrings && strings.Contains(trimmed, "$pattern = ") {
			// Extract regex pattern between /.../
			start := strings.Index(trimmed, "/")
			if start != -1 {
				end := strings.LastIndex(trimmed, "/")
				if end > start {
					patternStr = trimmed[start+1 : end]
				}
			}
		}
	}

	if id == "" || patternStr == "" {
		return nil, nil // Skip incomplete rules
	}

	// Convert severity string to proto enum
	severity := parseSeverity(severityStr)

	// Convert reason string to Reason type
	reasonType := Reason(reason)

	// Compile regex pattern
	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern for rule %s: %w", id, err)
	}

	return &UnsafePattern{
		Id:       id,
		Pattern:  pattern,
		Reason:   reasonType,
		Severity: severity,
	}, nil
}

// extractQuotedValue extracts a quoted string value from a line like: id = "value"
func extractQuotedValue(line string) string {
	start := strings.Index(line, "\"")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(line, "\"")
	if end > start {
		return line[start+1 : end]
	}
	return ""
}

// parseSeverity converts severity string to proto.RiskSeverity
func parseSeverity(severity string) proto.RiskSeverity {
	switch strings.ToLower(severity) {
	case "critical":
		return proto.RiskSeverity_RISK_SEVERITY_CRITICAL
	case "high":
		return proto.RiskSeverity_RISK_SEVERITY_HIGH
	case "medium":
		return proto.RiskSeverity_RISK_SEVERITY_MEDIUM
	case "low":
		return proto.RiskSeverity_RISK_SEVERITY_LOW
	default:
		return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}

func ToFindings(matches []UnsafeCommandMatch) []*proto.Finding {
	out := make([]*proto.Finding, 0, len(matches))
	for _, match := range matches {
		out = append(out, &proto.Finding{
			Tool:     "sast",
			Type:     proto.FindingType_FINDING_TYPE_SAST,
			Severity: match.Severity,
			RuleId:   match.PatternID,
			Title:    string(match.Reason),
			File:     match.File,
			Line:     match.Line,
			Message:  match.Match,
		})
	}
	return out
}
