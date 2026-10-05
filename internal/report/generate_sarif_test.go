package report

import (
	"encoding/json"
	"fmt"
	"testing"

	"mcpxray/proto"
)

func sampleFindings() []*proto.Finding {
	// Deliberately unordered by severity and by rule ID so the tests exercise
	// both the results-sort and the rules-sort rather than passing by luck.
	return []*proto.Finding{
		{RuleId: "rule-b", Title: "B", Severity: proto.RiskSeverity_RISK_SEVERITY_LOW},
		{RuleId: "rule-a", Title: "A", Severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL},
		{RuleId: "rule-c", Title: "C", Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM},
		{RuleId: "rule-a", Title: "A dup", Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH},
	}
}

// TestGenerateSarif_RulesArrayIsDeterministic locks in that the emitted rules
// array does not depend on Go's randomized map iteration order: the same
// logical input must produce byte-identical output across repeated calls.
func TestGenerateSarif_RulesArrayIsDeterministic(t *testing.T) {
	var first []byte
	for i := 0; i < 20; i++ {
		out, err := GenerateSarif(sampleFindings())
		if err != nil {
			t.Fatalf("GenerateSarif returned error on iteration %d: %v", i, err)
		}
		if first == nil {
			first = out
			continue
		}
		if string(out) != string(first) {
			t.Fatalf("GenerateSarif output differs across repeated calls with identical input (iteration %d)", i)
		}
	}
}

// TestGenerateSarif_RulesSortedByID checks the rules array is explicitly
// ordered by ID, not just "happens to be stable this run".
func TestGenerateSarif_RulesSortedByID(t *testing.T) {
	out, err := GenerateSarif(sampleFindings())
	if err != nil {
		t.Fatalf("GenerateSarif returned error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	rules := parsed.Runs[0].Tool.Driver.Rules
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID > rules[i].ID {
			t.Fatalf("rules not sorted by ID: %q appears before %q", rules[i-1].ID, rules[i].ID)
		}
	}
}

// TestGenerateSarifForTarget_TagsRelationsIncludingTestDependent covers all
// four targetRelation values GenerateSarifForTarget can produce, including
// the new "test-dependent" value for a finding inside a project included via
// targetresolve.InclusionTestDependent (internal/targetresolve/graph.go's
// includeTestDependents).
func TestGenerateSarifForTarget_TagsRelationsIncludingTestDependent(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "direct finding", File: "/repo/server/main.go"},
		{RuleId: "r2", Title: "shared finding", File: "/repo/shared/util.go"},
		{RuleId: "r3", Title: "test-dependent finding", File: "/repo/tests/server.tests/index.test.js"},
		{RuleId: "r4", Title: "repo-level finding", File: "/repo/README.md"},
		{RuleId: "r5", Title: "no file at all"},
	}
	reasons := map[string]string{
		"/repo/shared":             "shared-dependency",
		"/repo/tests/server.tests": "test-dependent",
	}

	out, err := GenerateSarifForTarget(findings, "/repo/server", []string{"/repo/server", "/repo/shared", "/repo/tests/server.tests"}, reasons)
	if err != nil {
		t.Fatalf("GenerateSarifForTarget returned error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	relationByRule := make(map[string]string)
	for _, r := range parsed.Runs[0].Results {
		relationByRule[r.RuleID] = fmt.Sprintf("%v", r.Properties["targetRelation"])
	}

	want := map[string]string{
		"r1": "direct",
		"r2": "shared-dependency",
		"r3": "test-dependent",
		"r4": "repo-level",
		"r5": "repo-level",
	}
	for rule, expected := range want {
		if got := relationByRule[rule]; got != expected {
			t.Errorf("rule %s: expected targetRelation %q, got %q", rule, expected, got)
		}
	}
}

// TestGenerateSarifForTarget_NilReasonsDegradesToSharedDependency locks in
// backward compatibility: a nil/empty reasons map (the pre-this-phase call
// shape) must behave exactly as before -- every included root other than
// primaryRoot reports "shared-dependency".
func TestGenerateSarifForTarget_NilReasonsDegradesToSharedDependency(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "shared finding", File: "/repo/shared/util.go"},
	}
	out, err := GenerateSarifForTarget(findings, "/repo/server", []string{"/repo/server", "/repo/shared"}, nil)
	if err != nil {
		t.Fatalf("GenerateSarifForTarget returned error: %v", err)
	}
	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}
	got := fmt.Sprintf("%v", parsed.Runs[0].Results[0].Properties["targetRelation"])
	if got != "shared-dependency" {
		t.Errorf("expected nil reasons to degrade to shared-dependency, got %q", got)
	}
}

// TestGenerateSarif_DoesNotMutateCallerSlice guards against GenerateSarif
// reordering the caller's findings slice in place as a side effect. Callers
// (e.g. the pentest flow) reuse the same slice immediately after calling
// this function and must see it in the order they passed it in.
func TestGenerateSarif_DoesNotMutateCallerSlice(t *testing.T) {
	findings := sampleFindings()

	wantOrder := make([]string, len(findings))
	for i, f := range findings {
		wantOrder[i] = f.RuleId
	}

	if _, err := GenerateSarif(findings); err != nil {
		t.Fatalf("GenerateSarif returned error: %v", err)
	}

	gotOrder := make([]string, len(findings))
	for i, f := range findings {
		gotOrder[i] = f.RuleId
	}

	for i := range wantOrder {
		if wantOrder[i] != gotOrder[i] {
			t.Fatalf("caller's findings slice was reordered by GenerateSarif: want %v, got %v", wantOrder, gotOrder)
		}
	}
}

// TestGenerateSarif_ResultsSortedBySeverityDescending checks the existing,
// intentional behavior (results ordered CRITICAL -> HIGH -> MEDIUM -> LOW)
// still holds now that sorting happens on a copy instead of in place.
func TestGenerateSarif_ResultsSortedBySeverityDescending(t *testing.T) {
	out, err := GenerateSarif(sampleFindings())
	if err != nil {
		t.Fatalf("GenerateSarif returned error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	levelRank := map[string]int{"error": 3, "warning": 2, "note": 1}
	results := parsed.Runs[0].Results
	for i := 1; i < len(results); i++ {
		if levelRank[results[i-1].Level] < levelRank[results[i].Level] {
			t.Fatalf("results not sorted by severity descending: %q (%s) appears before %q (%s)",
				results[i-1].RuleID, results[i-1].Level, results[i].RuleID, results[i].Level)
		}
	}
}

func TestGenerateSarifWithProperties_RunPropertiesInOutput(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "test finding", Severity: proto.RiskSeverity_RISK_SEVERITY_LOW, Tool: "sast"},
	}
	props := []map[string]interface{}{
		{"fingerprint": "abc123", "rawCount": 1, "targetIds": []string{"target-1"}},
	}
	runProps := map[string]interface{}{
		"targetSummaries": []map[string]interface{}{
			{"targetId": "target-1", "name": "server-a", "rawFindings": 1, "uniqueFindings": 1},
		},
		"executions": []map[string]interface{}{
			{"id": "exec-1", "scanner": "sast", "status": "success"},
		},
	}
	out, err := GenerateSarifWithProperties(findings, props, "/repo", runProps)
	if err != nil {
		t.Fatalf("GenerateSarifWithProperties returned error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	if parsed.Runs[0].Properties == nil {
		t.Fatal("run.properties is nil, expected targetSummaries and executions")
	}
	if _, ok := parsed.Runs[0].Properties["targetSummaries"]; !ok {
		t.Error("run.properties missing targetSummaries key")
	}
	if _, ok := parsed.Runs[0].Properties["executions"]; !ok {
		t.Error("run.properties missing executions key")
	}
}

func TestGenerateSarifWithProperties_NilRunPropertiesOmitted(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "test", Tool: "sast"},
	}
	props := []map[string]interface{}{{"fingerprint": "x"}}
	out, err := GenerateSarifWithProperties(findings, props, "/repo", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Runs[0].Properties != nil {
		t.Errorf("run.properties should be nil/omitted when runProperties is nil, got %v", parsed.Runs[0].Properties)
	}
}

func TestGenerateSarifWithProperties_PerFindingProperties(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "finding", Tool: "sast", File: "/repo/main.go", Line: 10},
	}
	props := []map[string]interface{}{
		{
			"fingerprint":    "fp-abc",
			"rawCount":       2,
			"duplicateCount": 1,
			"targetIds":      []string{"t1", "t2"},
			"componentIds":   []string{"comp-1"},
			"scanUnitIds":    []string{"su-1"},
			"relations":      []string{"direct", "shared"},
			"context":        []string{"production"},
			"rawInstances": []map[string]interface{}{
				{"scanUnitId": "su-1", "executionId": "exec-1", "scanner": "sast"},
				{"scanUnitId": "su-2", "executionId": "exec-2", "scanner": "sast"},
			},
		},
	}
	out, err := GenerateSarifWithProperties(findings, props, "/repo", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	result := parsed.Runs[0].Results[0]
	if result.Properties == nil {
		t.Fatal("result.properties is nil")
	}
	if fp, ok := result.Properties["fingerprint"].(string); !ok || fp != "fp-abc" {
		t.Errorf("fingerprint = %v, want fp-abc", result.Properties["fingerprint"])
	}
	if _, ok := result.Properties["rawInstances"]; !ok {
		t.Error("result.properties missing rawInstances key")
	}
}

// TestGenerateSarifWithProperties_PropertiesStayWithTheirFinding is the
// regression test for the bug where generateSarifWithProperties sorted
// findings by severity but indexed the parallel "additional" per-finding
// property slice by post-sort position, silently attaching one finding's
// fingerprint/targetIds/etc. to a different finding whenever severities
// differ. additional[i] must always describe findings[i], regardless of
// where findings[i] ends up in the output after severity sorting.
func TestGenerateSarifWithProperties_PropertiesStayWithTheirFinding(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "low-rule", Severity: proto.RiskSeverity_RISK_SEVERITY_LOW, File: "low.go"},
		{RuleId: "critical-rule", Severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL, File: "critical.go"},
		{RuleId: "medium-rule", Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM, File: "medium.go"},
	}
	props := []map[string]interface{}{
		{"fingerprint": "fp-for-low"},
		{"fingerprint": "fp-for-critical"},
		{"fingerprint": "fp-for-medium"},
	}
	want := map[string]string{
		"low-rule":      "fp-for-low",
		"critical-rule": "fp-for-critical",
		"medium-rule":   "fp-for-medium",
	}

	out, err := GenerateSarifWithProperties(findings, props, "", nil)
	if err != nil {
		t.Fatalf("GenerateSarifWithProperties returned error: %v", err)
	}
	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}
	if len(parsed.Runs[0].Results) != len(findings) {
		t.Fatalf("expected %d results, got %d", len(findings), len(parsed.Runs[0].Results))
	}
	seen := map[string]bool{}
	for _, result := range parsed.Runs[0].Results {
		seen[result.RuleID] = true
		gotFP, _ := result.Properties["fingerprint"].(string)
		if gotFP != want[result.RuleID] {
			t.Errorf("result %s: fingerprint = %q, want %q (properties attached to the wrong finding)", result.RuleID, gotFP, want[result.RuleID])
		}
	}
	for ruleID := range want {
		if !seen[ruleID] {
			t.Errorf("expected a result for %s, but it was missing from the output", ruleID)
		}
	}
}

// TestGenerateSarifWithProperties_EqualSeverityKeepsOriginalOrder locks in
// that the severity sort is stable: findings with equal severity keep their
// original relative order rather than shuffling on ties.
func TestGenerateSarifWithProperties_EqualSeverityKeepsOriginalOrder(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "first", Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM},
		{RuleId: "second", Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM},
		{RuleId: "third", Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM},
	}
	out, err := GenerateSarifWithProperties(findings, nil, "", nil)
	if err != nil {
		t.Fatalf("GenerateSarifWithProperties returned error: %v", err)
	}
	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}
	if len(parsed.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(parsed.Runs[0].Results))
	}
	got := []string{parsed.Runs[0].Results[0].RuleID, parsed.Runs[0].Results[1].RuleID, parsed.Runs[0].Results[2].RuleID}
	want := []string{"first", "second", "third"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result order = %v, want %v (equal-severity findings should keep their original order)", got, want)
			break
		}
	}
}

func TestGenerateSarif_LegacyPathNoRunProperties(t *testing.T) {
	out, err := GenerateSarif(sampleFindings())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Runs[0].Properties != nil {
		t.Errorf("GenerateSarif (legacy path) should never set run.properties, got %v", parsed.Runs[0].Properties)
	}
}

func TestGenerateSarifWithProperties_RelativePaths(t *testing.T) {
	findings := []*proto.Finding{
		{RuleId: "r1", Title: "inside repo", Tool: "sast", File: "/repo/src/main.go"},
		{RuleId: "r2", Title: "outside repo", Tool: "sast", File: "/other/file.go"},
	}
	props := []map[string]interface{}{{"fingerprint": "a"}, {"fingerprint": "b"}}
	out, err := GenerateSarifWithProperties(findings, props, "/repo", nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	for _, result := range parsed.Runs[0].Results {
		if result.RuleID == "r1" {
			uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if uri != "src/main.go" {
				t.Errorf("in-repo file should be relative, got %q", uri)
			}
		}
	}
}
