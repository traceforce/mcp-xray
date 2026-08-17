package reposcan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"mcpxray/proto"
)

type ScannerStatus string

const (
	ScannerSuccess     ScannerStatus = "success"
	ScannerFailed      ScannerStatus = "failed"
	ScannerSkipped     ScannerStatus = "skipped"
	ScannerUnsupported ScannerStatus = "unsupported"
	ScannerPartial     ScannerStatus = "partial"
)

type ScannerExecution struct {
	ID           string        `json:"id"`
	ScanUnitID   string        `json:"scanUnitId"`
	Scanner      string        `json:"scanner"`
	Status       ScannerStatus `json:"status"`
	FindingCount int           `json:"findingCount"`
	InputSummary string        `json:"inputSummary,omitempty"`
	DurationMs   int64         `json:"durationMs,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type DetailedScanResult struct {
	Findings   []*proto.Finding   `json:"-"`
	Executions []ScannerExecution `json:"executions"`
}

type ScannerSelection struct{ SCA, Secrets, SAST bool }

func executionID(scanUnitID, scanner string) string {
	sum := sha256.Sum256([]byte(scanUnitID + "\x00" + scanner))
	return "exec-" + hex.EncodeToString(sum[:8])
}

// ScanDetailed runs the same scanner entry points as the legacy path while
// retaining execution state. A failed scanner is never reported as zero
// findings, and successful raw findings are returned unchanged.
func ScanDetailed(ctx context.Context, root string, config *Config, selection ScannerSelection, scanUnitID string, inputSummary string) DetailedScanResult {
	result := DetailedScanResult{}
	run := func(name string, enabled bool, scan func() ([]*proto.Finding, error)) {
		execID := executionID(scanUnitID, name)
		if !enabled {
			result.Executions = append(result.Executions, ScannerExecution{ID: execID, ScanUnitID: scanUnitID, Scanner: name, Status: ScannerSkipped, InputSummary: inputSummary})
			return
		}
		start := time.Now()
		findings, err := scan()
		durationMs := time.Since(start).Milliseconds()
		if err != nil {
			if IsUnsupportedScanError(err) {
				result.Executions = append(result.Executions, ScannerExecution{ID: execID, ScanUnitID: scanUnitID, Scanner: name, Status: ScannerUnsupported, InputSummary: inputSummary, DurationMs: durationMs, Error: err.Error()})
				return
			}
			result.Executions = append(result.Executions, ScannerExecution{ID: execID, ScanUnitID: scanUnitID, Scanner: name, Status: ScannerFailed, InputSummary: inputSummary, DurationMs: durationMs, Error: err.Error()})
			return
		}
		result.Findings = append(result.Findings, findings...)
		result.Executions = append(result.Executions, ScannerExecution{ID: execID, ScanUnitID: scanUnitID, Scanner: name, Status: ScannerSuccess, InputSummary: inputSummary, DurationMs: durationMs, FindingCount: len(findings)})
	}
	run("osv", selection.SCA, func() ([]*proto.Finding, error) { return NewSCAScanner(root, config).Scan(ctx) })
	run("gitleaks", selection.Secrets, func() ([]*proto.Finding, error) { return NewSecretsScanner(root, config).Scan(ctx) })
	run("sast", selection.SAST, func() ([]*proto.Finding, error) { return NewSASTScanner(root, config).Scan(ctx) })
	return result
}

func (r DetailedScanResult) Err() error {
	for _, execution := range r.Executions {
		if execution.Status == ScannerFailed {
			return fmt.Errorf("%s scanner failed: %s", execution.Scanner, execution.Error)
		}
	}
	return nil
}
