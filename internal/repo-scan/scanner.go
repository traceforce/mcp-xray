package reposcan

import (
	"context"

	"SecureMCP/proto"
)

type RepoScanner struct {
	repoPath       string
	config         *Config
	scaScanner     *SCAScanner
	secretsScanner *SecretsScanner
	sastScanner    *SASTScanner
}

func NewDefaultRepoScanner(repoPath string) *RepoScanner {
	config := DefaultConfig()
	return NewRepoScannerWithConfig(repoPath, config)
}

func NewRepoScannerWithConfig(repoPath string, config *Config) *RepoScanner {
	return &RepoScanner{
		repoPath:       repoPath,
		config:         config,
		scaScanner:     NewSCAScanner(repoPath, config),
		secretsScanner: NewSecretsScanner(repoPath, config),
		sastScanner:    NewSASTScanner(repoPath, config),
	}
}

func (s *RepoScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	findings := []proto.Finding{}
	scaFindings, err := s.scaScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, scaFindings...)

	// Scan for secrets
	secretsFindings, err := s.secretsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, secretsFindings...)

	sastFindings, err := s.sastScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, sastFindings...)

	return findings, nil
}
