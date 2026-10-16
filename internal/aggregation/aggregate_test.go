package aggregation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"mcpxray/proto"
)

func TestAggregateExactDuplicateKeepsAffectedTargets(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "sast", Type: proto.FindingType_FINDING_TYPE_SAST, RuleId: "unsafe", File: filepath.Join(root, "shared", "util.go"), Line: 7, Message: "danger"}
	items := Aggregate(root, []AttributedFinding{
		{Finding: finding, TargetIDs: []string{"target-a"}, ScanUnitID: "scan-a", ExecutionID: "exec-a", Relation: "shared"},
		{Finding: finding, TargetIDs: []string{"target-b"}, ScanUnitID: "scan-b", ExecutionID: "exec-b", Relation: "shared"},
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
	// Each variant is a fresh message: proto messages embed a mutex and must
	// never be copied by value.
	newFinding := func() *proto.Finding {
		return &proto.Finding{Tool: "osv", Type: proto.FindingType_FINDING_TYPE_SCA, RuleId: "CVE-1", File: filepath.Join(root, "package-lock.json"), Package: "a", Version: "1", Message: "issue"}
	}
	base := newFinding()
	otherPackage := newFinding()
	otherPackage.Package = "b"
	otherLine := newFinding()
	otherLine.Line = 2
	if Fingerprint(root, base, 0) == Fingerprint(root, otherPackage, 0) {
		t.Error("different package instances must not share a fingerprint")
	}
	if Fingerprint(root, base, 0) == Fingerprint(root, otherLine, 0) {
		t.Error("different regions must not share a fingerprint")
	}
	if Fingerprint(root, base, 0) == Fingerprint(root, base, 1) {
		t.Error("different occurrences must not share a fingerprint")
	}
}

// A first occurrence hashes the finding's own fields alone, so a finding no
// execution repeats keeps the fingerprint it had before occurrences were
// counted, and a consumer tracking findings by fingerprint across reports
// still recognizes it.
func TestFingerprintOfAFirstOccurrenceHashesTheFindingAlone(t *testing.T) {
	root := t.TempDir()
	finding := &proto.Finding{Tool: "osv", Type: proto.FindingType_FINDING_TYPE_SCA, RuleId: "CVE-1", File: filepath.Join(root, "package-lock.json"), Package: "a", Version: "1", Message: "issue"}
	// tool, type, rule, path, line (none), package, version, message
	sum := sha256.Sum256([]byte(strings.Join([]string{"osv", "FINDING_TYPE_SCA", "CVE-1", "package-lock.json", "", "a", "1", "issue"}, "\x00")))
	if got, want := Fingerprint(root, finding, 0), hex.EncodeToString(sum[:16]); got != want {
		t.Errorf("Fingerprint = %s, want %s", got, want)
	}
}

// gitleaks reports two different secrets of one rule on one line as two
// findings nothing else tells apart. They stay two findings, and when an
// overlapping unit reports them too, each merges with its counterpart.
func TestAggregateKeepsOneExecutionsIdenticalFindingsApart(t *testing.T) {
	root := t.TempDir()
	newFinding := func() *proto.Finding {
		return &proto.Finding{Tool: "gitleaks", Type: proto.FindingType_FINDING_TYPE_SECRETS, RuleId: "aws-access-token", File: filepath.Join(root, "app", "keys.js"), Line: 3, Message: "AWS access token"}
	}
	first, second := newFinding(), newFinding()
	inputs := []AttributedFinding{
		{Finding: first, TargetIDs: []string{"t1"}, ScanUnitID: "su-1", ExecutionID: "exec-1"},
		{Finding: second, TargetIDs: []string{"t1"}, ScanUnitID: "su-1", ExecutionID: "exec-1"},
	}
	items := Aggregate(root, inputs)
	if len(items) != 2 || items[0].RawCount != 1 || items[1].RawCount != 1 {
		t.Fatalf("one execution's two identical findings aggregated to %d items, want 2 with one raw instance each", len(items))
	}

	inputs = append(inputs,
		AttributedFinding{Finding: newFinding(), TargetIDs: []string{"t2"}, ScanUnitID: "su-2", ExecutionID: "exec-2"},
		AttributedFinding{Finding: newFinding(), TargetIDs: []string{"t2"}, ScanUnitID: "su-2", ExecutionID: "exec-2"},
	)
	items = Aggregate(root, inputs)
	if len(items) != 2 {
		t.Fatalf("two executions' identical pairs aggregated to %d items, want 2", len(items))
	}
	fingerprints := map[string]bool{Fingerprint(root, first, 0): true, Fingerprint(root, first, 1): true}
	for _, item := range items {
		if item.RawCount != 2 || item.DuplicateCount != 1 || len(item.TargetIDs) != 2 {
			t.Errorf("item %+v, want one raw instance from each execution, crediting both targets", item)
		}
		if !fingerprints[item.Fingerprint] {
			t.Errorf("fingerprint %q is neither occurrence's", item.Fingerprint)
		}
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

// Directory tags must never be applied to the file name itself: these are
// ordinary production files that merely share a name with a tag.
func TestContextForPath_FileNamesAreNotDirectoryTags(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"src/test.go", "production"},
		{"src/build.go", "production"},
		{"src/tools.go", "production"},
		{"src/tools.ts", "production"},
		{"test.py", "production"},
		{"build", "production"},
		{"cmd/build", "production"},
		{"pkg/vendor.go", "production"},
		// tools/ is where MCP servers keep their tool handlers.
		{"tools/test.go", "production"},
		{"tools/Azure.Mcp.Tools.Storage/src/StorageService.cs", "production"},
		{"internal/test/helpers.go", "test"},
		{"docs/index.md", "docs"},
		{"README.md", "docs"},
		// Document names count only as documents, not as source files.
		{"internal/auth/security.go", "production"},
		{"src/history.ts", "production"},
		{"pkg/notice.py", "production"},
		{"server/changes.go", "production"},
		{"src/license.rs", "production"},
		{"SECURITY.md", "docs"},
		{"LICENSE", "docs"},
		{"pkg/CHANGELOG.rst", "docs"},
		{"NOTICE.txt", "docs"},
		// The outermost tagged directory decides.
		{"vendor/github.com/x/testing/y.go", "vendored"},
		{"scripts/docs/build.sh", "build"},
		{"examples/tests/demo.py", "example"},
	}
	for _, tc := range cases {
		if got := ContextForPath(tc.path); got != tc.want {
			t.Errorf("ContextForPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// A markup document is docs wherever it is; a file in no tagged directory is
// a test when its name follows its language's test convention; a directory
// is tagged only by its conventional lower-case name.
func TestContextForPath_DocumentsTestFilesAndNamespaces(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"src/server/USAGE.md", "docs"},
		// An agent skill is shipped instructions, not documentation.
		{"skills/stripe-directory/SKILL.md", "production"},
		{"plugins/cli/skills/sentry-cli/SKILL.md", "production"},
		{"docs/skills/example/SKILL.md", "docs"},
		{".devcontainer/devcontainer.json", "build"},
		{"packages/core/guide.mdx", "docs"},
		{"tests/README.md", "docs"},
		{"requirements.txt", "production"},
		{"src/handler_test.go", "test"},
		{"src/auth/token-cache.test.ts", "test"},
		{"src/sentry.spec.ts", "test"},
		{"pkg/test_server.py", "test"},
		{"pkg/server_test.py", "test"},
		{"pkg/conftest.py", "test"},
		{"src/latest.ts", "production"},
		{"src/main/java/io/mcp/server/AbstractMcpSyncServerTests.java", "test"},
		{"src/main/java/io/mcp/ServerTest.java", "test"},
		{"src/main/java/io/mcp/LifecycleTestCase.java", "test"},
		{"src/main/java/io/mcp/Latest.java", "production"},
		{"src/main/java/io/mcp/Contest.java", "production"},
		{"src/contest.py", "production"},
		{"src/spec.ts", "production"},
		{"examples/demo_test.go", "example"},
		{"tools/Azure.Mcp.Tools.Foo/tests/Azure.Mcp.Tools.Foo.Tests/FooTests.cs", "test"},
		{"src/Foo.UnitTests/BarTests.cs", "test"},
		{"src/Foo.Tests/BarTests.cs", "test"},
		{"src/Options/Docs/DocsGetOptions.cs", "production"},
		{"src/Webapp/Deployment/DeploymentGetCommand.cs", "production"},
		{"src/e2e/flow.ts", "test"},
		{"eng/common/scripts/x.ps1", "build"},
		{"docs_src/tutorial/server.py", "docs"},
	}
	for _, tc := range cases {
		if got := ContextForPath(tc.path); got != tc.want {
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
		{Finding: finding, TargetIDs: []string{"t1"}, ScanUnitID: "su-1", ExecutionID: "exec-1", Relation: "direct", Context: "production"},
		{Finding: finding, TargetIDs: []string{"t2"}, ScanUnitID: "su-2", ExecutionID: "exec-2", Relation: "shared", Context: "test"},
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

func TestSARIFProperties(t *testing.T) {
	item := &AggregatedFinding{
		Fingerprint:    "fp",
		RawCount:       2,
		DuplicateCount: 1,
		TargetIDs:      []string{"t-a"},
		ComponentIDs:   []string{"c-a"},
		ScanUnitIDs:    []string{"scan-a"},
		Relations:      []string{"direct"},
		Contexts:       []string{"production"},
	}
	properties := item.SARIFProperties()
	for _, key := range []string{"fingerprint", "rawCount", "duplicateCount", "targetIds", "componentIds", "scanUnitIds", "relations", "context"} {
		if _, ok := properties[key]; !ok {
			t.Errorf("SARIFProperties() lacks %q: %v", key, properties)
		}
	}
	if _, ok := properties["rawInstances"]; ok {
		t.Error("rawInstances is set although the finding has none")
	}

	item.RawInstances = []RawInstance{{ScanUnitID: "scan-a", ExecutionID: "exec-1", Scanner: "sast"}}
	if instances, ok := item.SARIFProperties()["rawInstances"].([]RawInstance); !ok || len(instances) != 1 {
		t.Errorf("rawInstances = %v, want the one raw instance", item.SARIFProperties()["rawInstances"])
	}
}

// A repository-global finding belongs to no target or component; its SARIF
// result says so with empty lists, not nulls.
func TestSARIFPropertiesEncodeEmptyListsAsArrays(t *testing.T) {
	data, err := json.Marshal((&AggregatedFinding{Fingerprint: "fp", RawCount: 1, ScanUnitIDs: []string{"scan-global"}, Relations: []string{"repository-global"}, Contexts: []string{"ci"}}).SARIFProperties())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"targetIds":[]`, `"componentIds":[]`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("SARIF properties %s lack %s", data, want)
		}
	}
	if strings.Contains(string(data), "null") {
		t.Errorf("SARIF properties %s hold a null", data)
	}
}
