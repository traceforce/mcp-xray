package tokenanalyzer

import (
	"regexp"
	"strings"
)

var nonWord = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeTokens(s string) []string {
	s = strings.ToLower(s)
	s = nonWord.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// ---- YARA-like rule model (no proto coupling here) ----

type StringType string

const (
	StringTokens StringType = "tokens"
)

type StringDef struct {
	Name   string     `yaml:"name" json:"name"`
	Type   StringType `yaml:"type" json:"type"`
	Values []string   `yaml:"values" json:"values"`
}

type ConditionKind string

const (
	CondAllPresent ConditionKind = "all_present"
	CondAnyPresent ConditionKind = "any_present"
	CondAnyNear    ConditionKind = "any_near"
)

type Condition struct {
	Kind   ConditionKind `yaml:"kind" json:"kind"`
	Names  []string      `yaml:"names" json:"names"`
	Window int           `yaml:"window,omitempty" json:"window,omitempty"`
}

// Rule is the in-memory YARA-like rule.
// We keep Severity as a string here and map it to proto.RiskSeverity later.
type Rule struct {
	ID        string            `yaml:"id" json:"id"`
	Severity  string            `yaml:"severity" json:"severity"` // "low", "medium", "high", "critical"
	Meta      map[string]string `yaml:"meta,omitempty" json:"meta,omitempty"`
	Strings   []StringDef       `yaml:"strings" json:"strings"`
	Condition Condition         `yaml:"condition" json:"condition"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// InternalFinding is what the engine emits before we map to proto.Finding.
type InternalFinding struct {
	RuleID   string
	Severity string            // same string as in rule.Severity ("low"/"high"/...)
	Meta     map[string]string // copied from rule.Meta
	Matches  map[string]int    // string ID -> count
}

// Analyze runs rules against text and returns internal findings.
func Analyze(text string, rules []Rule) []InternalFinding {
	tokens := normalizeTokens(text)

	var findings []InternalFinding

	for _, rule := range rules {
		matchPositions := make(map[string][]int) // stringID -> token positions

		for _, sdef := range rule.Strings {
			if sdef.Type == StringTokens {
				positions := matchTokenString(tokens, sdef.Values)
				if len(positions) > 0 {
					matchPositions[sdef.Name] = positions
				}
			}
		}

		if evalCondition(rule.Condition, matchPositions) {
			matches := make(map[string]int)
			for name, pos := range matchPositions {
				matches[name] = len(pos)
			}

			findings = append(findings, InternalFinding{
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Meta:     rule.Meta,
				Matches:  matches,
			})
		}
	}

	return findings
}

func matchTokenString(tokens []string, values []string) []int {
	if len(tokens) == 0 || len(values) == 0 {
		return nil
	}
	valSet := make(map[string]bool, len(values))
	for _, v := range values {
		valSet[v] = true
	}

	var positions []int
	for i, t := range tokens {
		if valSet[t] {
			positions = append(positions, i)
		}
	}
	return positions
}

func evalCondition(cond Condition, tokenMatches map[string][]int) bool {
	switch cond.Kind {
	case CondAllPresent:
		for _, name := range cond.Names {
			if !stringPresent(name, tokenMatches) {
				return false
			}
		}
		return true

	case CondAnyPresent:
		for _, name := range cond.Names {
			if stringPresent(name, tokenMatches) {
				return true
			}
		}
		return false

	case CondAnyNear:
		if cond.Window <= 0 || len(cond.Names) == 0 {
			return false
		}

		first := cond.Names[0]
		firstPos := tokenMatches[first]
		if len(firstPos) == 0 {
			return false
		}

		for _, anchor := range firstPos {
			allNear := true
			for _, name := range cond.Names[1:] {
				if !anyWithinWindow(anchor, tokenMatches[name], cond.Window) {
					allNear = false
					break
				}
			}
			if allNear {
				return true
			}
		}
		return false

	default:
		return false
	}
}

func stringPresent(name string, tokenMatches map[string][]int) bool {
	return len(tokenMatches[name]) > 0
}

func anyWithinWindow(anchor int, positions []int, window int) bool {
	if len(positions) == 0 {
		return false
	}
	for _, p := range positions {
		if p >= anchor-window && p <= anchor+window {
			return true
		}
	}
	return false
}
