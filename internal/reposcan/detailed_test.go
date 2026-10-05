package reposcan

import "testing"

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

func TestScannerExecutionFieldsPopulated(t *testing.T) {
	exec := ScannerExecution{
		ID:           executionID("su-1", "sast"),
		ScanUnitID:   "su-1",
		Scanner:      "sast",
		Status:       ScannerSkipped,
		InputSummary: "root=. manifests=1 lockfiles=0 files=5",
	}
	if exec.ID == "" {
		t.Error("execution ID should not be empty")
	}
	if exec.ScanUnitID != "su-1" {
		t.Errorf("scanUnitID = %q, want su-1", exec.ScanUnitID)
	}
	if exec.InputSummary == "" {
		t.Error("inputSummary should not be empty")
	}
}

func TestScannerStatusConstants(t *testing.T) {
	statuses := []ScannerStatus{ScannerSuccess, ScannerFailed, ScannerSkipped, ScannerUnsupported, ScannerPartial}
	seen := make(map[ScannerStatus]bool)
	for _, s := range statuses {
		if s == "" {
			t.Error("empty scanner status constant")
		}
		if seen[s] {
			t.Errorf("duplicate scanner status: %q", s)
		}
		seen[s] = true
	}
}
