package aggregation

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mcpxray/proto"
)

type AttributedFinding struct {
	Finding      *proto.Finding
	TargetIDs    []string
	ComponentIDs []string
	ScanUnitID   string
	ExecutionID  string
	Relation     string
	Context      string
}

type RawInstance struct {
	ScanUnitID  string `json:"scanUnitId"`
	ExecutionID string `json:"executionId"`
	Scanner     string `json:"scanner"`
}

type AggregatedFinding struct {
	Finding        *proto.Finding
	Fingerprint    string
	RawCount       int
	DuplicateCount int
	TargetIDs      []string
	ComponentIDs   []string
	ScanUnitIDs    []string
	Relations      []string
	Contexts       []string
	RawInstances   []RawInstance
}

func Fingerprint(repoRoot string, finding *proto.Finding) string {
	if finding == nil {
		return ""
	}
	path := finding.File
	if path != "" {
		if rel, err := filepath.Rel(repoRoot, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = filepath.ToSlash(rel)
		} else {
			path = filepath.ToSlash(filepath.Clean(path))
		}
	}
	message := strings.TrimSpace(finding.Message)
	if message == "" {
		message = strings.TrimSpace(finding.Title)
	}
	value := strings.Join([]string{finding.Tool, string(finding.Type.String()), finding.RuleId, path, formatInt(finding.Line), finding.Package, finding.Version, message}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func formatInt(value int32) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(int64(value), 10)
}

func Aggregate(repoRoot string, inputs []AttributedFinding) []*AggregatedFinding {
	byFingerprint := make(map[string]*AggregatedFinding)
	for _, input := range inputs {
		if input.Finding == nil {
			continue
		}
		fp := Fingerprint(repoRoot, input.Finding)
		agg := byFingerprint[fp]
		if agg == nil {
			agg = &AggregatedFinding{Finding: input.Finding, Fingerprint: fp}
			byFingerprint[fp] = agg
		}
		agg.RawCount++
		agg.TargetIDs = appendUnique(agg.TargetIDs, input.TargetIDs...)
		agg.ComponentIDs = appendUnique(agg.ComponentIDs, input.ComponentIDs...)
		agg.ScanUnitIDs = appendUnique(agg.ScanUnitIDs, input.ScanUnitID)
		agg.Relations = appendUnique(agg.Relations, input.Relation)
		agg.Contexts = appendUnique(agg.Contexts, input.Context)
		scanner := ""
		if input.Finding != nil {
			scanner = input.Finding.Tool
		}
		agg.RawInstances = append(agg.RawInstances, RawInstance{
			ScanUnitID:  input.ScanUnitID,
			ExecutionID: input.ExecutionID,
			Scanner:     scanner,
		})
	}
	result := make([]*AggregatedFinding, 0, len(byFingerprint))
	for _, value := range byFingerprint {
		value.DuplicateCount = value.RawCount - 1
		sort.Strings(value.TargetIDs)
		sort.Strings(value.ComponentIDs)
		sort.Strings(value.ScanUnitIDs)
		sort.Strings(value.Relations)
		sort.Strings(value.Contexts)
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Fingerprint < result[j].Fingerprint })
	return result
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

func ContextForPath(repoRelativePath string) string {
	path := strings.ToLower(filepath.ToSlash(repoRelativePath))
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	for _, docStem := range []string{
		"readme", "changelog", "changes", "contributing", "contributors",
		"license", "licence", "notice", "authors", "troubleshooting",
		"code_of_conduct", "code-of-conduct", "security", "history",
	} {
		if stem == docStem {
			return "docs"
		}
	}

	for _, tag := range contextDirectoryTags {
		for _, part := range strings.Split(path, "/") {
			if part == tag || strings.HasPrefix(part, tag+".") {
				return contextDirectoryToLabel[tag]
			}
		}
	}
	return "production"
}

var contextDirectoryTags = []string{
	"generated",
	"test", "tests", "__tests__", "testing", "testdata",
	"fixture", "fixtures", "testfixtures",
	"docs", "documentation", "doc",
	"examples", "example", "samples",
	".github", "ci", ".circleci", ".azure-pipelines",
	"scripts", "script", "tools",
	"deploy", "deployment", "infra", "terraform", "helm", "k8s",
	"build",
	"vendor", "third_party", "third-party", "external",
}

var contextDirectoryToLabel = map[string]string{
	"generated":          "generated",
	"test":               "test",
	"tests":              "test",
	"__tests__":          "test",
	"testing":            "test",
	"testdata":           "test",
	"fixture":            "fixture",
	"fixtures":           "fixture",
	"testfixtures":       "fixture",
	"docs":               "docs",
	"documentation":      "docs",
	"doc":                "docs",
	"examples":           "example",
	"example":            "example",
	"samples":            "example",
	".github":            "ci",
	"ci":                 "ci",
	".circleci":          "ci",
	".azure-pipelines":   "ci",
	"scripts":            "build",
	"script":             "build",
	"tools":              "build",
	"deploy":             "deployment",
	"deployment":         "deployment",
	"infra":              "deployment",
	"terraform":          "deployment",
	"helm":               "deployment",
	"k8s":                "deployment",
	"build":              "build",
	"vendor":             "vendored",
	"third_party":        "vendored",
	"third-party":        "vendored",
	"external":           "vendored",
}
