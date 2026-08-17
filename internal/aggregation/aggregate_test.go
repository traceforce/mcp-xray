package aggregation

import (
	"path/filepath"
	"testing"

	"mcpxray/proto"
)

func TestAggregateExactDuplicateKeepsAffectedTargets(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "sast", Type: proto.FindingType_FINDING_TYPE_SAST, RuleId: "unsafe", File: filepath.Join(root, "shared", "util.go"), Line: 7, Message: "danger"}
	items := Aggregate(root, []AttributedFinding{
		{Finding: finding, TargetIDs: []string{"target-a"}, ScanUnitID: "scan-shared", Relation: "shared"},
		{Finding: finding, TargetIDs: []string{"target-b"}, ScanUnitID: "scan-shared", Relation: "shared"},
	})
	if len(items) != 1 {
		t.Fatalf("aggregated findings = %d, want 1", len(items))
	}
	if items[0].RawCount != 2 || items[0].DuplicateCount != 1 {
		t.Errorf("raw/duplicate count = %d/%d, want 2/1", items[0].RawCount, items[0].DuplicateCount)
	}
	if len(items[0].TargetIDs) != 2 {
		t.Errorf("affected targets = %v, want both targets", items[0].TargetIDs)
	}
	if items[0].Finding != finding {
		t.Error("aggregation should preserve the original raw finding pointer")
	}
}

func TestFingerprintSeparatesPackagesAndRegions(t *testing.T) {
	root := t.TempDir()
	base := &proto.Finding{Tool: "osv", Type: proto.FindingType_FINDING_TYPE_SCA, RuleId: "CVE-1", File: filepath.Join(root, "package-lock.json"), Package: "a", Version: "1", Message: "issue"}
	otherPackage := *base
	otherPackage.Package = "b"
	otherLine := *base
	otherLine.Line = 2
	if Fingerprint(root, base) == Fingerprint(root, &otherPackage) {
		t.Error("different package instances must not share a fingerprint")
	}
	if Fingerprint(root, base) == Fingerprint(root, &otherLine) {
		t.Error("different regions must not share a fingerprint")
	}
}

func TestAggregateOwnershipBasedAttributionNoDuplication(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "sast", Type: proto.FindingType_FINDING_TYPE_SAST, RuleId: "unsafe", File: filepath.Join(root, "shared", "util.go"), Line: 7, Message: "danger"}
	items := Aggregate(root, []AttributedFinding{
		{Finding: finding, TargetIDs: []string{"target-a", "target-b"}, ComponentIDs: []string{"comp-shared"}, ScanUnitID: "scan-shared", ExecutionID: "exec-1", Relation: "shared", Context: "production"},
	})
	if len(items) != 1 {
		t.Fatalf("aggregated findings = %d, want 1", len(items))
	}
	if items[0].RawCount != 1 {
		t.Errorf("rawCount = %d, want 1 (single physical finding)", items[0].RawCount)
	}
	if items[0].DuplicateCount != 0 {
		t.Errorf("duplicateCount = %d, want 0", items[0].DuplicateCount)
	}
	if len(items[0].TargetIDs) != 2 {
		t.Errorf("targetIDs = %v, want [target-a target-b]", items[0].TargetIDs)
	}
}

func TestAggregateRawInstancesPreserveProvenance(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "sast", Type: proto.FindingType_FINDING_TYPE_SAST, RuleId: "unsafe", File: filepath.Join(root, "lib.go"), Line: 1, Message: "x"}
	items := Aggregate(root, []AttributedFinding{
		{Finding: finding, TargetIDs: []string{"t1"}, ScanUnitID: "su-1", ExecutionID: "exec-sast-1", Relation: "direct", Context: "production"},
		{Finding: finding, TargetIDs: []string{"t2"}, ScanUnitID: "su-2", ExecutionID: "exec-sast-2", Relation: "shared", Context: "production"},
	})
	if len(items) != 1 {
		t.Fatalf("aggregated findings = %d, want 1", len(items))
	}
	if len(items[0].RawInstances) != 2 {
		t.Fatalf("rawInstances = %d, want 2", len(items[0].RawInstances))
	}
	for _, ri := range items[0].RawInstances {
		if ri.ScanUnitID == "" || ri.ExecutionID == "" || ri.Scanner == "" {
			t.Errorf("rawInstance has empty fields: %+v", ri)
		}
	}
}

func TestContextForPath_DocFiles(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"README.md", "docs"},
		{"src/CHANGELOG.md", "docs"},
		{"CONTRIBUTING.rst", "docs"},
		{"LICENSE", "docs"},
		{"code_of_conduct.md", "docs"},
		{"SECURITY.md", "docs"},
		{"TROUBLESHOOTING.txt", "docs"},
	}
	for _, tc := range cases {
		got := ContextForPath(tc.path)
		if got != tc.want {
			t.Errorf("ContextForPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestContextForPath_DirectoryTags(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"src/main.go", "production"},
		{"tests/unit/foo_test.go", "test"},
		{"__tests__/bar.test.js", "test"},
		{"fixtures/data.json", "fixture"},
		{"docs/guide.md", "docs"},
		{"examples/demo.py", "example"},
		{".github/workflows/ci.yml", "ci"},
		{"deploy/helm/values.yaml", "deployment"},
		{"vendor/third-party/lib.go", "vendored"},
		{"scripts/build.sh", "build"},
		{"generated/api.pb.go", "generated"},
	}
	for _, tc := range cases {
		got := ContextForPath(tc.path)
		if got != tc.want {
			t.Errorf("ContextForPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestContextForPath_SameFileNeverTwoContexts(t *testing.T) {
	path := "docs/README.md"
	got := ContextForPath(path)
	if got != "docs" {
		t.Errorf("ContextForPath(%q) = %q, want docs (file+dir agree)", path, got)
	}
}

func TestAggregateZeroFindingsReturnsEmpty(t *testing.T) {
	items := Aggregate("/repo", nil)
	if len(items) != 0 {
		t.Errorf("aggregate of nil input = %d, want 0", len(items))
	}
	items = Aggregate("/repo", []AttributedFinding{})
	if len(items) != 0 {
		t.Errorf("aggregate of empty input = %d, want 0", len(items))
	}
}

func TestAggregateCollectsAllRelationsAndContexts(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "sast", Type: proto.FindingType_FINDING_TYPE_SAST, RuleId: "r1", File: filepath.Join(root, "shared", "f.go"), Message: "x"}
	items := Aggregate(root, []AttributedFinding{
		{Finding: finding, TargetIDs: []string{"t1"}, ScanUnitID: "su-1", Relation: "direct", Context: "production"},
		{Finding: finding, TargetIDs: []string{"t2"}, ScanUnitID: "su-2", Relation: "shared", Context: "test"},
	})
	if len(items) != 1 {
		t.Fatalf("aggregated = %d, want 1", len(items))
	}
	if len(items[0].Relations) != 2 {
		t.Errorf("relations = %v, want [direct shared]", items[0].Relations)
	}
	if len(items[0].Contexts) != 2 {
		t.Errorf("contexts = %v, want [production test]", items[0].Contexts)
	}
}
