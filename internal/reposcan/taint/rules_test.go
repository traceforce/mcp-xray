package taint

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGeneratePythonRulesValidYAML(t *testing.T) {
	out, err := generatePythonRules([]string{"command_injection", "ssrf"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc ogRuleDoc
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(doc.Rules))
	}
	for _, r := range doc.Rules {
		if r.Mode != "taint" {
			t.Errorf("rule %s: mode = %q, want taint", r.ID, r.Mode)
		}
		if len(r.Sources) == 0 || len(r.Sinks) == 0 {
			t.Errorf("rule %s: missing sources or sinks", r.ID)
		}
	}
}

func TestGeneratePythonRulesDefaultsAndSkipsUnknown(t *testing.T) {
	out, err := generatePythonRules([]string{"not_a_class"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var doc ogRuleDoc
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Rules) != 0 {
		t.Fatalf("unknown class should yield no rules, got %d", len(doc.Rules))
	}
}
