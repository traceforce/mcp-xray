package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"mcpxray/internal/metadata"
	"mcpxray/proto"
)

// SARIFReport represents the SARIF 2.1.0 report structure
type SARIFReport struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool       Tool                   `json:"tool"`
	Results    []Result               `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	InformationURI string          `json:"informationUri,omitempty"`
	Rules          []ReportingRule `json:"rules,omitempty"`
}

type ReportingRule struct {
	ID               string   `json:"id"`
	Name             *Message `json:"name,omitempty"`
	ShortDescription *Message `json:"shortDescription,omitempty"`
}

type Result struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level,omitempty"`
	Message    Message                `json:"message"`
	Locations  []Location             `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

// GenerateSarifWithProperties is the additive reporting path used by the
// multi-target planner. The input findings are still the original scanner
// findings; properties carry attribution/fingerprint/context separately.
// runProperties, when non-nil, is attached to the SARIF Run object so
// target summaries, scan plans and execution records are visible in output
// even when a target produces zero findings.
func GenerateSarifWithProperties(findings []*proto.Finding, properties []map[string]interface{}, repoRoot string, runProperties map[string]interface{}) ([]byte, error) {
	return generateSarifWithProperties(findings, nil, properties, repoRoot, runProperties)
}

// GenerateSarif builds a SARIF report from findings. Used by config-scan,
// pentest, verify, and the legacy (no target-resolution) repo-scan path.
func GenerateSarif(findings []*proto.Finding) ([]byte, error) {
	return generateSarifWithProperties(findings, nil, nil, "", nil)
}

// GenerateSarifForTarget builds a SARIF report the same way GenerateSarif
// does, additionally tagging each result with how it relates to a resolved
// target-resolution target (internal/targetresolve): "direct" for a finding
// inside the selected server's own directory, "test-dependent" for a finding
// inside a test/tooling project that depends on the server rather than the
// reverse (targetresolve.InclusionTestDependent), "shared-dependency" for a
// finding inside any other included directory (a workspace-local dependency
// the server needs), and "repo-level" for anything else (or a finding with
// no file path at all). This is additive -- GenerateSarif's own signature
// and output are untouched, so config-scan, pentest, and verify require no
// changes.
//
// reasons maps a cleaned included directory to why it was included
// (targetresolve.Target.IncludedReasons); a nil or empty map degrades
// gracefully to the original direct/shared-dependency/repo-level behavior
// (every included root not equal to primaryRoot is reported as
// "shared-dependency", as before).
func GenerateSarifForTarget(findings []*proto.Finding, primaryRoot string, includedRoots []string, reasons map[string]string) ([]byte, error) {
	primaryRoot = filepath.Clean(primaryRoot)
	cleanedIncluded := make([]string, len(includedRoots))
	for i, r := range includedRoots {
		cleanedIncluded[i] = filepath.Clean(r)
	}

	relation := func(findingFile string) string {
		if findingFile == "" {
			return "repo-level"
		}
		cleaned := filepath.Clean(findingFile)
		if isWithinRoot(cleaned, primaryRoot) {
			return "direct"
		}
		for _, root := range cleanedIncluded {
			if isWithinRoot(cleaned, root) {
				reason := reasons[root]
				if reason == "" {
					reason = reasons[filepath.ToSlash(root)]
				}
				if reason == "test-dependent" {
					return "test-dependent"
				}
				return "shared-dependency"
			}
		}
		return "repo-level"
	}

	return generateSarifWithProperties(findings, relation, nil, "", nil)
}

// isWithinRoot reports whether path is root itself or lives under it.
func isWithinRoot(path, root string) bool {
	path, root = filepath.ToSlash(filepath.Clean(path)), filepath.ToSlash(filepath.Clean(root))
	return path == root || strings.HasPrefix(path, root+"/")
}

// generateSarif is the shared implementation behind GenerateSarif and
// GenerateSarifForTarget. relation is nil for the plain (non-target-scoped)
// path; when non-nil, it is called with each finding's File to compute a
// "targetRelation" SARIF property.
func generateSarif(findings []*proto.Finding, relation func(findingFile string) string) ([]byte, error) {
	return generateSarifWithProperties(findings, relation, nil, "", nil)
}

func generateSarifWithProperties(findings []*proto.Finding, relation func(findingFile string) string, additional []map[string]interface{}, repoRoot string, runProperties map[string]interface{}) ([]byte, error) {
	// Build rules map
	ruleMap := make(map[string]*ReportingRule)
	for i := range findings {
		finding := findings[i]
		if finding.RuleId == "" {
			continue
		}
		if _, exists := ruleMap[finding.RuleId]; !exists {
			rule := &ReportingRule{
				ID: finding.RuleId,
			}
			if finding.Title != "" {
				rule.ShortDescription = &Message{Text: finding.Title}
			}
			ruleMap[finding.RuleId] = rule
		}
	}

	// Convert rules map to slice, sorted by ID so the output is deterministic
	// across runs (Go map iteration order is randomized per-process).
	rules := make([]ReportingRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, *rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	// Sort by severity (descending; proto values are in descending order) via
	// an index permutation rather than reordering findings/additional
	// directly. additional[i] is the per-finding property map for
	// findings[i]; sorting findings alone (as this used to do) desyncs that
	// pairing the moment two findings differ in severity, silently attaching
	// fingerprint/targetIds/etc. to the wrong finding in the output. Indices
	// keep both slices addressable by their original position, so the pairing
	// survives the reorder, and neither the caller's findings slice nor
	// additional is mutated -- callers such as the pentest flow reuse findings
	// immediately after this call and should not see it silently reordered as
	// a side effect of report generation. SliceStable keeps equal-severity
	// findings in their original order, matching sort.Slice's prior behavior
	// on ties (Go's sort.Slice is not guaranteed stable, but for equal keys
	// the practical difference doesn't matter here; SliceStable just makes it
	// deterministic).
	order := make([]int, len(findings))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return findings[order[i]].Severity > findings[order[j]].Severity
	})

	// Convert findings to results
	results := make([]Result, 0, len(order))
	for _, idx := range order {
		finding := findings[idx]

		result := Result{
			RuleID: finding.RuleId,
			Level:  mapSeverityToLevel(finding.Severity),
		}

		// Set message
		message := finding.Message
		if message == "" {
			message = finding.Title
		}
		if message == "" {
			message = fmt.Sprintf("Security finding: %s", finding.RuleId)
		}
		result.Message = Message{Text: message}

		// Add location if file is specified
		if finding.File != "" {
			uri := finding.File
			if repoRoot != "" {
				if rel, err := filepath.Rel(repoRoot, finding.File); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					uri = filepath.ToSlash(rel)
				}
			}
			location := Location{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: uri,
					},
				},
			}

			// Add region if line is specified
			if finding.Line > 0 {
				location.PhysicalLocation.Region = &Region{
					StartLine: int(finding.Line),
				}
			}

			result.Locations = []Location{location}
		}

		// Add properties with additional metadata
		properties := make(map[string]interface{})
		properties["tool"] = finding.Tool
		properties["type"] = findingTypeToString(finding.Type)
		if finding.McpServerName != "" {
			properties["mcpServerName"] = finding.McpServerName
		}
		if finding.McpToolName != "" {
			properties["mcpToolName"] = finding.McpToolName
		}
		if finding.Package != "" {
			properties["package"] = finding.Package
		}
		if finding.Version != "" {
			properties["version"] = finding.Version
		}
		if finding.Fixed != "" {
			properties["fixed"] = finding.Fixed
		}
		if relation != nil {
			properties["targetRelation"] = relation(finding.File)
		}
		if additional != nil && idx < len(additional) {
			for key, value := range additional[idx] {
				properties[key] = value
			}
		}
		if len(properties) > 0 {
			result.Properties = properties
		}

		results = append(results, result)
	}

	// Build the SARIF report
	run := Run{
		Tool: Tool{
			Driver: Driver{
				Name:           metadata.Name,
				Version:        metadata.Version,
				InformationURI: metadata.InformationURI,
				Rules:          rules,
			},
		},
		Results:    results,
		Properties: runProperties,
	}
	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []Run{run},
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return jsonBytes, nil
}

// mapSeverityToLevel converts RiskSeverity to SARIF level
func mapSeverityToLevel(severity proto.RiskSeverity) string {
	switch severity {
	case proto.RiskSeverity_RISK_SEVERITY_CRITICAL:
		return "error"
	case proto.RiskSeverity_RISK_SEVERITY_HIGH:
		return "error"
	case proto.RiskSeverity_RISK_SEVERITY_MEDIUM:
		return "warning"
	case proto.RiskSeverity_RISK_SEVERITY_LOW:
		return "note"
	default:
		return "note"
	}
}

// findingTypeToString converts FindingType to string
func findingTypeToString(findingType proto.FindingType) string {
	switch findingType {
	case proto.FindingType_FINDING_TYPE_SCA:
		return "SCA"
	case proto.FindingType_FINDING_TYPE_SECRETS:
		return "SECRETS"
	case proto.FindingType_FINDING_TYPE_SAST:
		return "SAST"
	case proto.FindingType_FINDING_TYPE_TOOL_ANALYSIS:
		return "TOOL_ANALYSIS"
	case proto.FindingType_FINDING_TYPE_CONNECTION:
		return "CONNECTION"
	case proto.FindingType_FINDING_TYPE_PENTEST:
		return "PENTEST"
	default:
		return "UNKNOWN"
	}
}
