package verify

import (
	"encoding/json"
	"os"

	"mcpxray/proto"
)

// ParseSarifToFindings parses a SARIF file and returns a slice of proto.Finding.
func ParseSarifToFindings(sarifPath string) ([]*proto.Finding, error) {
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, err
	}

	var report struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region,omitempty"`
					} `json:"physicalLocation"`
				} `json:"locations,omitempty"`
				Properties map[string]interface{} `json:"properties,omitempty"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription *struct {
							Text string `json:"text"`
						} `json:"shortDescription,omitempty"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	ruleMap := make(map[string]string)
	if len(report.Runs) > 0 {
		for _, rule := range report.Runs[0].Tool.Driver.Rules {
			if rule.ShortDescription != nil {
				ruleMap[rule.ID] = rule.ShortDescription.Text
			}
		}
	}

	var findings []*proto.Finding
	if len(report.Runs) > 0 {
		for _, result := range report.Runs[0].Results {
			finding := &proto.Finding{
				RuleId:  result.RuleID,
				Title:   ruleMap[result.RuleID],
				Message: result.Message.Text,
			}

			switch result.Level {
			case "error":
				finding.Severity = proto.RiskSeverity_RISK_SEVERITY_CRITICAL
			case "warning":
				finding.Severity = proto.RiskSeverity_RISK_SEVERITY_HIGH
			case "note":
				finding.Severity = proto.RiskSeverity_RISK_SEVERITY_MEDIUM
			default:
				finding.Severity = proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
			}

			if len(result.Locations) > 0 {
				loc := result.Locations[0]
				finding.File = loc.PhysicalLocation.ArtifactLocation.URI
				if loc.PhysicalLocation.Region != nil {
					finding.Line = int32(loc.PhysicalLocation.Region.StartLine)
				}
			}

			if props := result.Properties; props != nil {
				if tool, ok := props["tool"].(string); ok {
					finding.Tool = tool
				}
				if mcpServer, ok := props["mcpServerName"].(string); ok {
					finding.McpServerName = mcpServer
				}
				if mcpTool, ok := props["mcpToolName"].(string); ok {
					finding.McpToolName = mcpTool
				}
				if typeStr, ok := props["type"].(string); ok {
					switch typeStr {
					case "PENTEST":
						finding.Type = proto.FindingType_FINDING_TYPE_PENTEST
					case "SAST":
						finding.Type = proto.FindingType_FINDING_TYPE_SAST
					case "SCA":
						finding.Type = proto.FindingType_FINDING_TYPE_SCA
					case "SECRETS":
						finding.Type = proto.FindingType_FINDING_TYPE_SECRETS
					case "TOOL_ANALYSIS":
						finding.Type = proto.FindingType_FINDING_TYPE_TOOL_ANALYSIS
					case "CONNECTION":
						finding.Type = proto.FindingType_FINDING_TYPE_CONNECTION
					default:
						finding.Type = proto.FindingType_FINDING_TYPE_UNKNOWN
					}
				} else {
					finding.Type = proto.FindingType_FINDING_TYPE_PENTEST
				}
			} else {
				finding.Type = proto.FindingType_FINDING_TYPE_PENTEST
			}

			if finding.Title == "" {
				finding.Title = result.Message.Text
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}
