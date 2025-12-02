package reposcan

import (
	"context"
	"fmt"

	"SecureMCP/proto"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type SecretsScanner struct {
	repoPath string
	config   *Config
}

func NewSecretsScanner(repoPath string, config *Config) *SecretsScanner {
	return &SecretsScanner{
		repoPath: repoPath,
		config:   config,
	}
}

func (s *SecretsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// 1) Load default config (same rules as CLI when no custom config is provided)
	// NewDetectorDefaultConfig creates a detector with the default ruleset.
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	// 2) Use gitleaks' built-in directory scanning which properly handles:
	//    - Binary file filtering
	//    - Large file skipping
	//    - Allowlist/ignore patterns
	//    - Symlink handling
	//    - Archive extraction
	dirSource := sources.Files{
		Path:           s.repoPath,
		Config:         &detector.Config,
		Sema:           detector.Sema,
		FollowSymlinks: detector.FollowSymlinks,
		MaxFileSize:    detector.MaxTargetMegaBytes * 1_000_000, // Convert MB to bytes
	}

	allFindings, err := detector.DetectSource(ctx, &dirSource)
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan error: %w", err)
	}

	// 3) Convert findings to string slice
	fmt.Printf("Gitleaks found %d secrets\n", len(allFindings))
	findings := FromGitleaks(allFindings)

	return findings, nil
}

func FromGitleaks(findings []report.Finding) []proto.Finding {
	out := make([]proto.Finding, 0, len(findings))

	for _, f := range findings {
		out = append(out, proto.Finding{
			Tool:     "gitleaks",
			Type:     proto.FindingType_FINDING_TYPE_SECRETS,
			Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH, // treat all secrets as high/error
			RuleId:   f.RuleID,
			Title:    f.Description,
			File:     f.File,
			Line:     int32(f.StartLine),
			Message:  f.Description, // avoid empty message
		})
	}

	return out
}
