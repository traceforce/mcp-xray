package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"mcpxray/proto"
)

var oneFinding = []*proto.Finding{{RuleId: "AUTH-MISSING", Title: "t", Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH}}

func render(t *testing.T, outcomes []Outcome) ([]byte, Run) {
	t.Helper()
	b, err := GenerateSarif(oneFinding, outcomes)
	if err != nil {
		t.Fatal(err)
	}
	var rep SARIFReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	return b, rep.Runs[0]
}

func TestGenerateSarifNilOutcomes(t *testing.T) {
	got, _ := render(t, nil)
	if bytes.Contains(got, []byte(`"kind"`)) || bytes.Contains(got, []byte(`"invocations"`)) {
		t.Fatalf("nil outcomes must add no kind or invocations:\n%s", got)
	}
}

func TestGenerateSarifOutcomes(t *testing.T) {
	props := map[string]any{"phase": "tools/call"}
	_, run := render(t, []Outcome{{RuleID: "AUTH-MISSING", Kind: "review", Reason: "r", Properties: props}})
	if len(run.Results) != 2 || run.Results[0].Kind != "" || len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 0 {
		t.Fatalf("want the finding, one outcome result and one successful invocation, got results %+v invocations %+v", run.Results, run.Invocations)
	}
	if r := run.Results[1]; r.RuleID != "AUTH-MISSING" || r.Kind != "review" || r.Level != "none" || r.Message.Text != "r" || r.Properties["phase"] != "tools/call" {
		t.Errorf("review outcome rendered as %+v", r)
	}
	_, run = render(t, []Outcome{{RuleID: "AUTH-MISSING", Kind: "errored", Reason: "e", Properties: props}})
	if len(run.Results) != 1 || len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("errored outcome must be a notification only with executionSuccessful false, got results %+v invocations %+v", run.Results, run.Invocations)
	}
	if n := run.Invocations[0].ToolExecutionNotifications; len(n) != 1 || n[0].Level != "error" || n[0].Descriptor.ID != "AUTH-MISSING" || n[0].Message.Text != "e" || n[0].Properties["phase"] != "tools/call" {
		t.Fatalf("notifications = %+v", n)
	}
	if _, err := GenerateSarif(oneFinding, []Outcome{{RuleID: "AUTH-MISSING", Kind: "maybe"}}); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}
