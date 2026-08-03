package taint

import (
	"fmt"

	"mcpxray/proto"
)

// classInfo maps a taint class to its report fields. case_id is the
// vuln_rules.case_id seeded from internal/pentest/test_categories.csv, so a finding's
// rule_id resolves with no migration.
type classInfo struct {
	caseID   string
	severity proto.RiskSeverity
	title    string
}

var classInfoByVC = map[string]classInfo{
	"command_injection": {"INJECTION-COMMAND", proto.RiskSeverity_RISK_SEVERITY_CRITICAL, "Command injection"},
	"code_injection":    {"INJECTION-CODE", proto.RiskSeverity_RISK_SEVERITY_CRITICAL, "Code injection"},
	"path_traversal":    {"INJECTION-PATH", proto.RiskSeverity_RISK_SEVERITY_HIGH, "Path traversal"},
	"sqli":              {"INJECTION-SQL", proto.RiskSeverity_RISK_SEVERITY_HIGH, "SQL injection"},
	"ssrf":              {"SSRF-INTERNAL", proto.RiskSeverity_RISK_SEVERITY_HIGH, "Server-side request forgery"},
	"secret_exposure":   {"INFO-SECRETS-LEAK", proto.RiskSeverity_RISK_SEVERITY_MEDIUM, "Secret exposure"},
}

// PathsToFindings converts taint paths into proto.Findings, mapping the class to its
// rule_id/severity/title and attributing to the handler function as mcp_tool_name.
func PathsToFindings(paths []PathRecord) []*proto.Finding {
	out := make([]*proto.Finding, 0, len(paths))
	for _, p := range paths {
		info, ok := classInfoByVC[p.VulnClass]
		if !ok {
			// Unknown class (e.g. a future CodeQL tag): never leave severity unset.
			info = classInfo{caseID: p.VulnClass, severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM, title: p.VulnClass}
		}
		out = append(out, &proto.Finding{
			Tool:        p.Engine,
			Type:        proto.FindingType_FINDING_TYPE_SAST,
			Severity:    info.severity,
			RuleId:      info.caseID,
			Title:       fmt.Sprintf("%s: MCP tool input reaches %s", info.title, p.SinkAPI),
			McpToolName: p.SourceFunction,
			File:        p.SinkFile,
			Line:        int32(p.SinkLine),
			Message:     message(p),
		})
	}
	return out
}

func message(p PathRecord) string {
	msg := fmt.Sprintf("Tainted MCP tool input `%s` in handler `%s` reaches %s sink `%s` at %s:%d.",
		p.SourceParam, p.SourceFunction, p.VulnClass, p.SinkAPI, p.SinkFile, p.SinkLine)
	if p.IsCrossFile {
		msg += " (cross-file flow)"
	}
	return msg
}
