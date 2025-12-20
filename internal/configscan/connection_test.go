package configscan

import (
	"crypto/tls"
	"fmt"
	"testing"

	"mcpxray/internal/libmcp"
	"mcpxray/proto"

	"github.com/stretchr/testify/assert"
)

func TestCheckCertificate(t *testing.T) {
	scanner := NewConnectionScanner("/test/config.json")

	t.Run("Invalid TLS certificate", func(t *testing.T) {
		url := "https://expired.badssl.com/"
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test Invalid TLS certificate: expected 1 finding, got %d", len(findings)))
		assert.Equal(t, "invalid-certificate", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
	})

	t.Run("Untrusted root TLS certificate", func(t *testing.T) {
		url := "https://untrusted-root.badssl.com/"
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test untrusted TLS certificate: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, "invalid-certificate", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
	})
}

func TestCheckTLSVersion_WithTLS(t *testing.T) {
	url := "https://mcp.asana.com/mcp"

	scanner := NewConnectionScanner("/test/config.json")
	cfg := libmcp.MCPServerConfig{
		Name: "test-server",
		URL:  &url,
	}

	t.Run("TLS 1.1", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS11, cfg)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(findings), fmt.Sprintf("Test TLS 1.1: expected 1 finding, got %d", len(findings)))
		if len(findings) > 0 {
			t.Logf("Test TLS 1.1: %+v", findings)
		}
	})
	t.Run("TLS 1.2", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS12, cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test TLS 1.2: expected 1 finding, got %d", len(findings)))
		if len(findings) > 0 {
			assert.Equal(t, "tls-version-1.2-detected", findings[0].RuleId)
			assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_MEDIUM, findings[0].Severity)
			assert.Equal(t, "connection-scanner", findings[0].Tool)
			assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
			assert.Equal(t, "test-server", findings[0].McpServerName)
			assert.Equal(t, "/test/config.json", findings[0].File)
		}
	})
	t.Run("TLS 1.3", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS13, cfg)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(findings), fmt.Sprintf("Test TLS 1.3: expected 0 findings, got %d", len(findings)))
	})

}

func TestCheckCertificate_ConnectionError(t *testing.T) {
	scanner := NewConnectionScanner("/test/config.json")
	invalidURL := "https://invalid-domain-that-does-not-exist-12345.com"
	cfg := libmcp.MCPServerConfig{
		Name: "test-server",
		URL:  &invalidURL,
	}

	findings, err := scanner.checkCertificate(cfg)
	assert.Nil(t, err)
	t.Logf("Test connection error: %v", err)
	assert.Equal(t, 1, len(findings), fmt.Sprintf("Test connection error: expected 1 findings, got %d", len(findings)))
	assert.Equal(t, "connection-failed-no-response", findings[0].RuleId)
	assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
	assert.Equal(t, "connection-scanner", findings[0].Tool)
	assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
	assert.Equal(t, "test-server", findings[0].McpServerName)
	assert.Equal(t, "/test/config.json", findings[0].File)
}

func TestDetectIdentityControl(t *testing.T) {
	t.Run("Test Asana MCP server", func(t *testing.T) {
		url := "https://mcp.asana.com/sse"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 2, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, "oauth-coarse-grained-scopes", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_HIGH, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
		assert.Equal(t, "oauth-scopes-not-configured", findings[1].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_HIGH, findings[1].Severity)
		assert.Equal(t, "connection-scanner", findings[1].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[1].Type)
		assert.Equal(t, "test-server", findings[1].McpServerName)
		assert.Equal(t, "/test/config.json", findings[1].File)
	})

	t.Run("Test Github MCP server", func(t *testing.T) {
		url := "https://api.githubcopilot.com/mcp/"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 2, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, "oauth-write-scope-detected", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_MEDIUM, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "Write scope detected in PRM", findings[0].Title)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
	})

	t.Run("Test Supabase MCP server", func(t *testing.T) {
		url := "https://mcp.supabase.com/mcp"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 2, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, "oauth-write-scope-detected", findings[1].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_MEDIUM, findings[1].Severity)
		assert.Equal(t, "connection-scanner", findings[1].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[1].Type)
		assert.Equal(t, "Write scope detected in ASMD", findings[1].Title)
		assert.Equal(t, "test-server", findings[1].McpServerName)
		assert.Equal(t, "/test/config.json", findings[1].File)
	})

	t.Run("Test No authentication", func(t *testing.T) {
		url := "https://www.google.com"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, "no-authentication", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_HIGH, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
	})
}
