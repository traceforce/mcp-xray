package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mcpxray/proto"
)

func TestExecutionIDDeterministic(t *testing.T) {
	id1 := executionID("scan-unit-1", "sast")
	id2 := executionID("scan-unit-1", "sast")
	if id1 != id2 {
		t.Errorf("executionID not deterministic: %q vs %q", id1, id2)
	}
	if id1 == "" {
		t.Error("executionID returned empty string")
	}
	if id1[:5] != "exec-" {
		t.Errorf("executionID missing prefix: %q", id1)
	}
}

func TestExecutionIDDistinct(t *testing.T) {
	id1 := executionID("unit-a", "sast")
	id2 := executionID("unit-a", "osv")
	id3 := executionID("unit-b", "sast")
	if id1 == id2 {
		t.Error("same unit, different scanner must produce different IDs")
	}
	if id1 == id3 {
		t.Error("same scanner, different unit must produce different IDs")
	}
}

func TestScanDetailed_TagsEveryFindingWithItsExecution(t *testing.T) {
	root := t.TempDir()
	// Split so this file is not itself reported as containing a token.
	token := "gh" + "p_" + "8sR2kQ9vLx4TzW7nB1mYc5pD3fH6jE0aK2uV"
	if err := os.WriteFile(filepath.Join(root, "config.py"), []byte("GITHUB_TOKEN = \""+token+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Root = root
	result := ScanDetailed(context.Background(), root, config, ScannerSelection{Secrets: true}, "unit-1", "")

	if len(result.Executions) != 3 {
		t.Fatalf("executions = %d, want one per scanner (3)", len(result.Executions))
	}
	statuses := map[string]ScannerStatus{}
	var secrets ScannerExecution
	for _, execution := range result.Executions {
		statuses[execution.Scanner] = execution.Status
		if execution.Scanner == "gitleaks" {
			secrets = execution
		}
	}
	if statuses["osv"] != ScannerSkipped || statuses["sast"] != ScannerSkipped || statuses["gitleaks"] != ScannerSuccess {
		t.Fatalf("statuses = %v, want osv and sast skipped, gitleaks success", statuses)
	}
	if len(result.Findings) == 0 || secrets.FindingCount != len(result.Findings) {
		t.Fatalf("findings = %d, gitleaks FindingCount = %d; want the same, non-zero", len(result.Findings), secrets.FindingCount)
	}
	for _, finding := range result.Findings {
		if finding.ExecutionID != secrets.ID {
			t.Errorf("finding %s has execution %q, want %q", finding.Finding.RuleId, finding.ExecutionID, secrets.ID)
		}
	}
}

func TestScanRootOwnFilesDetailed_RecordsOneOSVExecution(t *testing.T) {
	result := ScanRootOwnFilesDetailed(t.TempDir(), "workspace-root-fallback", "")
	if len(result.Executions) != 1 {
		t.Fatalf("executions = %d, want 1", len(result.Executions))
	}
	execution := result.Executions[0]
	if execution.Scanner != "osv" || execution.ScanUnitID != "workspace-root-fallback" || execution.Status != ScannerUnsupported {
		t.Errorf("execution = %+v, want an unsupported osv execution of workspace-root-fallback", execution)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings = %d, want none for an empty directory", len(result.Findings))
	}
}

// The taint engines report a file relative to the directory they scanned;
// every recorded finding is located absolutely, whichever scanner found it.
func TestRun_MakesScanRootRelativeFilesAbsolute(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unit")
	elsewhere := filepath.Join(t.TempDir(), "b.py")
	var result DetailedScanResult
	result.run(root, "unit-1", "sast", "", true, func() ([]*proto.Finding, error) {
		return []*proto.Finding{{File: filepath.Join("src", "a.py")}, {File: elsewhere}, {}}, nil
	})
	want := []string{filepath.Join(root, "src", "a.py"), elsewhere, ""}
	for i, finding := range result.Findings {
		if finding.Finding.File != want[i] {
			t.Errorf("finding %d file = %q, want %q", i, finding.Finding.File, want[i])
		}
	}
}
