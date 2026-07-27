package reposcan

import (
	"context"

	"mcpxray/proto"
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
	if config == nil {
		config = DefaultConfig()
	}
	// Work on a copy so we never mutate the caller's Config: Root is per scan root, and a
	// shared/reused config would otherwise get the wrong Root or race across scans. The
	// ExcludedPaths slice is only read, so a shallow copy is safe to share.
	cfg := *config
	if cfg.Root == "" {
		cfg.Root = repoPath // scope excludes to the repo (see Config.Root)
	}
	return &RepoScanner{
		repoPath:       repoPath,
		config:         &cfg,
		scaScanner:     NewSCAScanner(repoPath, &cfg),
		secretsScanner: NewSecretsScanner(repoPath, &cfg),
		sastScanner:    NewSASTScanner(repoPath, &cfg),
	}
}

func (s *RepoScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	findings := []*proto.Finding{}
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
