package configscan

import (
	"context"

	"SecureMCP/proto"
)

type ConfigScanner struct {
	configPath   string
	toolsScanner *ToolsScanner
}

func NewConfigScanner(configPath string, scannerConfig *ScannerConfig) *ConfigScanner {
	return &ConfigScanner{
		configPath:   configPath,
		toolsScanner: NewToolsScanner(configPath, scannerConfig),
	}
}

func NewDefaultConfigScanner(configPath string) *ConfigScanner {
	return NewConfigScanner(configPath, NewScannerConfig(&UserAccount{Uid: "501", Username: "xiahua"}))
}

func (s *ConfigScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	findings := []proto.Finding{}
	toolsFindings, err := s.toolsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, toolsFindings...)

	return findings, nil
}
