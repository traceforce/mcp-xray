package taint

import (
	"testing"

	"mcpxray/proto"
)

func TestPathsToFindings(t *testing.T) {
	paths := []PathRecord{{
		VulnClass:      "command_injection",
		SourceFunction: "run_ping",
		SourceParam:    "host",
		SinkFile:       "server.py",
		SinkLine:       12,
		SinkAPI:        "os.system",
		Engine:         "opengrep",
	}}
	f := PathsToFindings(paths)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	got := f[0]
	if got.RuleId != "INJECTION-COMMAND" {
		t.Errorf("rule_id = %q, want INJECTION-COMMAND (case_id for vuln_rules)", got.RuleId)
	}
	if got.Type != proto.FindingType_FINDING_TYPE_SAST {
		t.Errorf("type = %v, want SAST", got.Type)
	}
	if got.Severity != proto.RiskSeverity_RISK_SEVERITY_CRITICAL {
		t.Errorf("severity = %v, want CRITICAL", got.Severity)
	}
	if got.McpToolName != "run_ping" {
		t.Errorf("mcp_tool_name = %q, want run_ping (non-empty NOT NULL)", got.McpToolName)
	}
	if got.Line != 12 || got.File != "server.py" {
		t.Errorf("location = %s:%d, want server.py:12", got.File, got.Line)
	}
}
