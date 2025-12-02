package reposcan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"SecureMCP/proto"
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

// unsafePattern represents a pattern that indicates unsafe system commands
type unsafePattern struct {
	id       string
	pattern  *regexp.Regexp
	reason   Reason
	severity proto.RiskSeverity
}

// normalizeForPatternMatching normalizes command text to catch obfuscation attempts
func normalizeForPatternMatching(text string) string {
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

// unsafeSystemPatterns contains patterns for commands that can modify critical system configurations
// macOS-focused patterns (Darwin collector)
var unsafeSystemPatterns = []unsafePattern{
	// Critical - System destruction or complete compromise
	{
		id:       "rm_rf_root",
		pattern:  regexp.MustCompile(`\brm\b.*(-r|-rf|-fr).*(/\s|/\*|--no-preserve-root)`),
		reason:   ReasonDestructiveFileOps,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "csrutil_disable",
		pattern:  regexp.MustCompile(`\bcsrutil\s+(disable|clear)\b`),
		reason:   ReasonSystemSecurityBypass,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "nvram_modify",
		pattern:  regexp.MustCompile(`\bnvram\s+(set-variable|-d|-c|boot-args)`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "dd_device",
		pattern:  regexp.MustCompile(`\bdd\b[^\n]*\b(of|if)=/dev/r?disk\d+(s\d+)?\b`),
		reason:   ReasonDestructiveFileOps,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "curl_pipe_shell",
		pattern:  regexp.MustCompile(`\b(curl|wget)\b[^\n]*\|\s*\b(sh|bash|zsh|tcsh)\b`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "process_substitution_shell",
		pattern:  regexp.MustCompile(`\b(sh|bash|zsh|tcsh)\b\s*<\s*\(\s*\b(curl|wget)\b`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "kext_load",
		pattern:  regexp.MustCompile(`\b(kextload|kextutil)\b`),
		reason:   ReasonSystemSecurityBypass,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},

	// High - Significant system changes or security bypass
	{
		id:       "spctl_disable",
		pattern:  regexp.MustCompile(`\bspctl\s+(--master-disable|--disable|--global-disable)`),
		reason:   ReasonSystemSecurityBypass,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "tccutil_reset",
		pattern:  regexp.MustCompile(`\btccutil\s+(reset|remove)`),
		reason:   ReasonSystemSecurityBypass,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "diskutil_destructive",
		pattern:  regexp.MustCompile(`\bdiskutil\s+(erase|erasedisk|erasevolume|partition|zerodisk|randomdisk|secureerase)\b`),
		reason:   ReasonDestructiveFileOps,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "asr_restore",
		pattern:  regexp.MustCompile(`\basr\s+(restore|imagescan)`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "chmod_777",
		pattern:  regexp.MustCompile(`\bchmod\b.*(777|a\+rwx|go\+w)`),
		reason:   ReasonInsecureFilePerms,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "rm_rf",
		pattern:  regexp.MustCompile(`\brm\b.*(-rf|-fr|-r\s+-f|-f\s+-r)`),
		reason:   ReasonDestructiveFileOps,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "killall",
		pattern:  regexp.MustCompile(`\bkillall\b`),
		reason:   ReasonProcessManagement,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "profiles_remove",
		pattern:  regexp.MustCompile(`\bprofiles\s+(-D|-R|remove|delete)\b`),
		reason:   ReasonServiceManagement,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "launchctl_bootout",
		pattern:  regexp.MustCompile(`\blaunchctl\s+(bootout|remove|unload)\b`),
		reason:   ReasonServiceManagement,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "shutdown_reboot",
		pattern:  regexp.MustCompile(`\b(shutdown|reboot|halt)\b`),
		reason:   ReasonSystemControl,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "tmutil_disable",
		pattern:  regexp.MustCompile(`\btmutil\s+(disable|disablelocal|delete)\b`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "installer_pkg_root",
		pattern:  regexp.MustCompile(`\binstaller\b[^\n]*\b(-pkg|--package)\b[^\n]*\b(-target|--target)\s*/(?:\s|$)`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},

	// Medium - Elevated privileges or service management
	{
		id:       "sudo",
		pattern:  regexp.MustCompile(`\bsudo\b`),
		reason:   ReasonPrivilegeEscalation,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "doas",
		pattern:  regexp.MustCompile(`\bdoas\b`),
		reason:   ReasonPrivilegeEscalation,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "kill_force",
		pattern:  regexp.MustCompile(`\bkill\s+(-9|-kill|-sigkill)\b`),
		reason:   ReasonProcessManagement,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "launchctl_modify",
		pattern:  regexp.MustCompile(`\blaunchctl\s+(stop|disable|kickstart|bootstrap)\b`),
		reason:   ReasonServiceManagement,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "chown_recursive",
		pattern:  regexp.MustCompile(`\bchown\s+(-R|-r)\b`),
		reason:   ReasonFileOwnershipChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "osascript",
		pattern:  regexp.MustCompile(`\bosascript\b`),
		reason:   ReasonSystemAutomation,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "shell_exec",
		pattern:  regexp.MustCompile(`\b(bash|sh|zsh|tcsh)\s+-c\b`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "python_exec",
		pattern:  regexp.MustCompile(`\bpython3?\s+(-c|-m\s+code)`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "defaults_write",
		pattern:  regexp.MustCompile(`\bdefaults\s+write\b`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "pmset",
		pattern:  regexp.MustCompile(`\bpmset\b`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "networksetup",
		pattern:  regexp.MustCompile(`\bnetworksetup\b`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "scutil",
		pattern:  regexp.MustCompile(`\bscutil\b`),
		reason:   ReasonSystemConfigChanges,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},

	// Low - Package management and less risky operations
	{
		id:       "brew_install",
		pattern:  regexp.MustCompile(`\bbrew\s+(install|upgrade|tap)\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},
	{
		id:       "npm_global",
		pattern:  regexp.MustCompile(`\bnpm\s+i(nstall)?\s+(-g|--global)\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},
	{
		id:       "pip_install",
		pattern:  regexp.MustCompile(`\bpip3?\s+install\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},
	{
		id:       "gem_install",
		pattern:  regexp.MustCompile(`\bgem\s+install\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},
	{
		id:       "cargo_install",
		pattern:  regexp.MustCompile(`\bcargo\s+install\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},
	{
		id:       "port_install",
		pattern:  regexp.MustCompile(`\bport\s+install\b`),
		reason:   ReasonPackageInstallation,
		severity: proto.RiskSeverity_RISK_SEVERITY_LOW,
	},

	// Python-specific security patterns
	{
		id:       "python_eval",
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "python_exec",
		pattern:  regexp.MustCompile(`\bexec\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "python_pickle_loads",
		pattern:  regexp.MustCompile(`\bpickle\.(loads?|Unpickler)\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "python_subprocess_shell",
		pattern:  regexp.MustCompile(`\bsubprocess\.(Popen|call|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_os_system",
		pattern:  regexp.MustCompile(`\bos\.system\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_compile",
		pattern:  regexp.MustCompile(`\bcompile\s*\([^)]*,\s*['"]`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_marshal_loads",
		pattern:  regexp.MustCompile(`\bmarshal\.loads?\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_yaml_load",
		pattern:  regexp.MustCompile(`\byaml\.(load|unsafe_load|FullLoader)\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_sql_injection",
		pattern:  regexp.MustCompile(`\b(execute|executemany)\s*\([^)]*[%+]`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "python_deserialize",
		pattern:  regexp.MustCompile(`\b(__import__|getattr|setattr|delattr)\s*\([^)]*['"]`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},

	// Node.js-specific security patterns
	{
		id:       "nodejs_eval",
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "nodejs_function_constructor",
		pattern:  regexp.MustCompile(`\bnew\s+Function\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
	{
		id:       "nodejs_child_process_exec",
		pattern:  regexp.MustCompile(`\bchild_process\.(exec|execSync|spawn|spawnSync)\s*\(`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "nodejs_settimeout_string",
		pattern:  regexp.MustCompile(`\b(setTimeout|setInterval)\s*\([^,)]*['"]`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "nodejs_require_dynamic",
		pattern:  regexp.MustCompile(`\brequire\s*\(\s*[^'"][^)]*\)`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "nodejs_fs_writefile",
		pattern:  regexp.MustCompile(`\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(`),
		reason:   ReasonDestructiveFileOps,
		severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
	},
	{
		id:       "nodejs_serialize_eval",
		pattern:  regexp.MustCompile(`\b(eval|Function)\s*\([^)]*JSON\.(parse|stringify)`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "nodejs_vm_runincontext",
		pattern:  regexp.MustCompile(`\bvm\.(runInContext|runInNewContext|runInThisContext)\s*\(`),
		reason:   ReasonCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
	},
	{
		id:       "nodejs_express_eval",
		pattern:  regexp.MustCompile(`\bexpress\s*\([^)]*\)[^}]*eval\s*\(`),
		reason:   ReasonRemoteCodeExecution,
		severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
	},
}

// DetectUnsafeCommands analyzes content for unsafe system commands and returns matches with file/line info
func DetectUnsafeCommands(ctx context.Context, filePath string, content string) []UnsafeCommandMatch {
	// Normalize to catch obfuscation attempts
	lines := strings.Split(content, "\n")

	var matches []UnsafeCommandMatch
	seen := make(map[string]int) // Track pattern ID -> line number to avoid duplicates per file

	for lineNum, line := range lines {
		normalizedLine := normalizeForPatternMatching(line)
		for _, pattern := range unsafeSystemPatterns {
			if pattern.pattern.MatchString(normalizedLine) {
				// Check if we've already seen this pattern in this file
				key := pattern.id
				if prevLine, exists := seen[key]; exists {
					// Only report if this is a different line (allow multiple instances)
					if prevLine == lineNum+1 {
						continue
					}
				}

				// Find the actual match in the original line
				match := pattern.pattern.FindString(normalizedLine)
				if match == "" {
					match = pattern.pattern.FindString(line)
				}
				if match == "" {
					match = "unsafe command detected"
				}

				matches = append(matches, UnsafeCommandMatch{
					PatternID: pattern.id,
					Reason:    pattern.reason,
					Severity:  pattern.severity,
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
func (s *SASTScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	var allMatches []UnsafeCommandMatch

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
	return FromSAST(allMatches), nil
}

func FromSAST(matches []UnsafeCommandMatch) []proto.Finding {
	out := make([]proto.Finding, 0, len(matches))
	for _, match := range matches {
		out = append(out, proto.Finding{
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
