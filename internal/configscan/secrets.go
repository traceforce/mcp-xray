package configscan

import (
	"context"
	"fmt"
	"strings"

	"mcpxray/internal/libmcp"
	"mcpxray/proto"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type SecretsScanner struct {
	configPath string
}

func NewSecretsScanner(configPath string) *SecretsScanner {
	return &SecretsScanner{
		configPath: configPath,
	}
}

func (s *SecretsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	servers, err := libmcp.NewConfigParser(s.configPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Secrets scanner scanning %d MCP servers\n", len(servers))

	findings := []proto.Finding{}
	for _, server := range servers {
		findings = append(findings, DetectSecrets(server, s.configPath)...)
	}

	return findings, nil
}

func DetectSecrets(cfg libmcp.MCPServerConfig, configPath string) []proto.Finding {
	fmt.Printf("Scanning secrets for server %s\n", cfg.Name)

	if strings.TrimSpace(cfg.RawJSON) == "" {
		return []proto.Finding{}
	}

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil
	}

	results := detector.DetectString(cfg.RawJSON)

	return FromGitleaks(cfg, results, configPath)
}

func FromGitleaks(cfg libmcp.MCPServerConfig, findings []report.Finding, configPath string) []proto.Finding {
	out := make([]proto.Finding, 0, len(findings))

	for _, f := range findings {
		message := f.Description
		if message == "" {
			message = fmt.Sprintf("A potential secret was detected in the MCP server configuration '%s' using rule '%s'. Secrets in configuration files pose a security risk and should be removed or stored securely.", cfg.Name, f.RuleID)
		}

		out = append(out, proto.Finding{
			Tool:          "gitleaks",
			McpServerName: cfg.Name,
			Type:          proto.FindingType_FINDING_TYPE_SECRETS,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH, // treat all secrets as high/error
			RuleId:        f.RuleID,
			Title:         f.Description,
			File:          configPath,
			Line:          int32(f.StartLine),
			Message:       message,
		})
	}

	fmt.Printf("Secrets scanner found %d findings\n", len(out))

	return out
}
