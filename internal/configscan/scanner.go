package configscan

import (
	"context"

	"mcpxray/proto"
)

type ConfigScanner struct {
	configPath        string
	secretsScanner    *SecretsScanner
	connectionScanner *ConnectionScanner
	toolsScanner      *ToolsScanner
}

func NewConfigScanner(configPath string, analyzerType string, model string, toolsOutputFile string) (*ConfigScanner, error) {
	toolsScanner, err := NewToolsScanner(configPath, analyzerType, model, toolsOutputFile)
	if err != nil {
		return nil, err
	}

	return &ConfigScanner{
		configPath:        configPath,
		secretsScanner:    NewSecretsScanner(configPath),
		connectionScanner: NewConnectionScanner(configPath),
		toolsScanner:      toolsScanner,
	}, nil
}

func (s *ConfigScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	findings := []proto.Finding{}

	connectionFindings, err := s.connectionScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, connectionFindings...)

	toolsFindings, err := s.toolsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, toolsFindings...)

	secretsFindings, err := s.secretsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, secretsFindings...)

	return findings, nil
}
