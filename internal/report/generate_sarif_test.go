package report

import (
	"encoding/json"
	"testing"
)

func TestGenerateSarifSkipped(t *testing.T) {
	var r SARIFReport
	b, err := GenerateSarif(nil, "server s: session could not be created")
	if err != nil || json.Unmarshal(b, &r) != nil {
		t.Fatal(err)
	}
	if inv := r.Runs[0].Invocations; len(inv) != 1 || inv[0].ExecutionSuccessful || inv[0].ToolExecutionNotifications[0].Message.Text != "server s: session could not be created" {
		t.Fatalf("invocations = %+v, want one unsuccessful invocation carrying the reason", inv)
	}
	b, _ = GenerateSarif(nil)
	r = SARIFReport{}
	if json.Unmarshal(b, &r) != nil || r.Runs[0].Invocations != nil {
		t.Fatalf("a run with nothing skipped carries invocations: %s", b)
	}
}
