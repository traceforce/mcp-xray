package report

import (
	"encoding/json"
	"fmt"
	"sort"

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
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
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

func GenerateSarif(findings []*proto.Finding) ([]byte, error) {
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

	// Convert rules map to slice
	rules := make([]ReportingRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, *rule)
	}

	// sort rules by severity. The proto values are in descending order.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	// Convert findings to results
	results := make([]Result, 0, len(findings))
	for i := range findings {
		finding := findings[i]

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
			location := Location{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: finding.File,
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
		if len(properties) > 0 {
			result.Properties = properties
		}

		results = append(results, result)
	}

	// Build the SARIF report
	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           metadata.Name,
						Version:        metadata.Version,
						InformationURI: metadata.InformationURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
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
