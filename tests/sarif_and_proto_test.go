package tests

import (
	"encoding/json"
	"testing"

	"mcpxray/internal/report"
	scanpb "mcpxray/proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------------------------
// GenerateSarif — originalRuleId property (new code in generate_sarif.go)
// ---------------------------------------------------------------------------

func TestGenerateSarif_OriginalRuleIdInProperties(t *testing.T) {
	findings := []*scanpb.Finding{
		{
			Tool:           "pentest",
			Type:           scanpb.FindingType_FINDING_TYPE_PENTEST,
			Severity:       scanpb.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:         "INJECTION-INDIRECT",
			Title:          "Indirect injection",
			Message:        "Evidence proves indirect injection",
			OriginalRuleId: "SSRF-LOCALHOST",
		},
	}

	sarifBytes, err := report.GenerateSarif(findings)
	require.NoError(t, err)

	var sarifReport map[string]interface{}
	err = json.Unmarshal(sarifBytes, &sarifReport)
	require.NoError(t, err)

	runs := sarifReport["runs"].([]interface{})
	require.Len(t, runs, 1)
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	require.Len(t, results, 1)

	props, ok := results[0].(map[string]interface{})["properties"].(map[string]interface{})
	require.True(t, ok, "result should have properties")
	assert.Equal(t, "SSRF-LOCALHOST", props["originalRuleId"],
		"originalRuleId should appear in SARIF properties")
}

func TestGenerateSarif_OriginalRuleIdAbsent_WhenEmpty(t *testing.T) {
	findings := []*scanpb.Finding{
		{
			Tool:     "pentest",
			Type:     scanpb.FindingType_FINDING_TYPE_PENTEST,
			Severity: scanpb.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:   "PATH-TRAVERSAL",
			Title:    "Path traversal",
			Message:  "test message",
			// OriginalRuleId is empty — should NOT appear in properties
		},
	}

	sarifBytes, err := report.GenerateSarif(findings)
	require.NoError(t, err)

	var sarifReport map[string]interface{}
	err = json.Unmarshal(sarifBytes, &sarifReport)
	require.NoError(t, err)

	runs := sarifReport["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	props, ok := results[0].(map[string]interface{})["properties"].(map[string]interface{})
	require.True(t, ok)

	_, exists := props["originalRuleId"]
	assert.False(t, exists, "originalRuleId should NOT be in properties when empty")
}

func TestGenerateSarif_OriginalRuleIdCoexistsWithOtherProperties(t *testing.T) {
	findings := []*scanpb.Finding{
		{
			Tool:           "pentest",
			Type:           scanpb.FindingType_FINDING_TYPE_SCA,
			Severity:       scanpb.RiskSeverity_RISK_SEVERITY_CRITICAL,
			RuleId:         "INJECTION-INDIRECT",
			Title:          "Reclassified finding",
			Message:        "test",
			Package:        "some-package",
			Version:        "1.0.0",
			Fixed:          "1.0.1",
			OriginalRuleId: "SSRF-LOCALHOST",
			McpServerName:  "test-server",
			McpToolName:    "read_rss",
		},
	}

	sarifBytes, err := report.GenerateSarif(findings)
	require.NoError(t, err)

	var sarifReport map[string]interface{}
	err = json.Unmarshal(sarifBytes, &sarifReport)
	require.NoError(t, err)

	runs := sarifReport["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	props := results[0].(map[string]interface{})["properties"].(map[string]interface{})

	// All properties should coexist
	assert.Equal(t, "SSRF-LOCALHOST", props["originalRuleId"])
	assert.Equal(t, "some-package", props["package"])
	assert.Equal(t, "1.0.0", props["version"])
	assert.Equal(t, "1.0.1", props["fixed"])
	assert.Equal(t, "test-server", props["mcpServerName"])
	assert.Equal(t, "read_rss", props["mcpToolName"])
	assert.Equal(t, "pentest", props["tool"])
	assert.Equal(t, "SCA", props["type"])
}

// ---------------------------------------------------------------------------
// SARIF schema version and structure
// ---------------------------------------------------------------------------

func TestGenerateSarif_SchemaVersion(t *testing.T) {
	findings := []*scanpb.Finding{
		{
			Tool:           "pentest",
			RuleId:         "TEST",
			Title:          "Test",
			OriginalRuleId: "ORIGINAL",
			Severity:       scanpb.RiskSeverity_RISK_SEVERITY_LOW,
		},
	}

	sarifBytes, err := report.GenerateSarif(findings)
	require.NoError(t, err)

	var sarifReport map[string]interface{}
	err = json.Unmarshal(sarifBytes, &sarifReport)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", sarifReport["version"])
	assert.Contains(t, sarifReport["$schema"].(string), "sarif-schema-2.1.0")
}

// ---------------------------------------------------------------------------
// Proto Finding — OriginalRuleId field (new field 14)
// ---------------------------------------------------------------------------

func TestProtoFinding_OriginalRuleId_SetAndGet(t *testing.T) {
	finding := &scanpb.Finding{
		RuleId:         "INJECTION-INDIRECT",
		OriginalRuleId: "SSRF-LOCALHOST",
	}

	assert.Equal(t, "INJECTION-INDIRECT", finding.GetRuleId())
	assert.Equal(t, "SSRF-LOCALHOST", finding.GetOriginalRuleId())
}

func TestProtoFinding_OriginalRuleId_DefaultEmpty(t *testing.T) {
	finding := &scanpb.Finding{
		RuleId: "PATH-TRAVERSAL",
	}

	assert.Equal(t, "", finding.GetOriginalRuleId())
}

func TestProtoFinding_OriginalRuleId_Serialization_Roundtrip(t *testing.T) {
	original := &scanpb.Finding{
		Tool:           "pentest",
		Type:           scanpb.FindingType_FINDING_TYPE_PENTEST,
		Severity:       scanpb.RiskSeverity_RISK_SEVERITY_HIGH,
		RuleId:         "INJECTION-INDIRECT",
		Title:          "Reclassified finding",
		Message:        "Evidence proves indirect injection",
		OriginalRuleId: "SSRF-LOCALHOST",
	}

	// Serialize
	data, err := proto.Marshal(original)
	require.NoError(t, err)

	// Deserialize
	restored := &scanpb.Finding{}
	err = proto.Unmarshal(data, restored)
	require.NoError(t, err)

	assert.Equal(t, original.GetOriginalRuleId(), restored.GetOriginalRuleId())
	assert.Equal(t, original.GetRuleId(), restored.GetRuleId())
	assert.Equal(t, original.GetTool(), restored.GetTool())
	assert.Equal(t, original.GetTitle(), restored.GetTitle())
	assert.Equal(t, original.GetSeverity(), restored.GetSeverity())
	assert.Equal(t, original.GetMessage(), restored.GetMessage())
}

func TestProtoFinding_OriginalRuleId_EmptyDoesNotSerialize(t *testing.T) {
	withEmpty := &scanpb.Finding{
		RuleId:         "TEST",
		OriginalRuleId: "",
	}

	withoutField := &scanpb.Finding{
		RuleId: "TEST",
	}

	data1, err := proto.Marshal(withEmpty)
	require.NoError(t, err)

	data2, err := proto.Marshal(withoutField)
	require.NoError(t, err)

	// Empty string field should serialize identically to unset field
	assert.Equal(t, data1, data2, "Empty OriginalRuleId should serialize same as unset")
}
