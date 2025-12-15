package configscan

import (
	"crypto/tls"
	"fmt"
	"testing"

	configparser "mcpxray/internal/configparser"
	"mcpxray/proto"

	"github.com/stretchr/testify/assert"
)

func TestCheckCertificate(t *testing.T) {
	scanner := NewConnectionScanner("/test/config.json")

	t.Run("Invalid TLS certificate", func(t *testing.T) {
		url := "https://expired.badssl.com/"
		cfg := configparser.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, len(findings), 1, fmt.Sprintf("Test Invalid TLS certificate: expected 1 finding, got %d", len(findings)))
		assert.Equal(t, findings[0].RuleId, "invalid-certificate")
		assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_CRITICAL)
		assert.Equal(t, findings[0].Tool, "connection-scanner")
		assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
		assert.Equal(t, findings[0].McpServerName, "test-server")
		assert.Equal(t, findings[0].File, "/test/config.json")
	})

	t.Run("Untrusted root TLS certificate", func(t *testing.T) {
		url := "https://untrusted-root.badssl.com/"
		cfg := configparser.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test untrusted TLS certificate: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, findings[0].RuleId, "invalid-certificate")
		assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_CRITICAL)
		assert.Equal(t, findings[0].Tool, "connection-scanner")
		assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
		assert.Equal(t, findings[0].McpServerName, "test-server")
		assert.Equal(t, findings[0].File, "/test/config.json")
	})
}

func TestCheckTLSVersion_WithTLS(t *testing.T) {
	url := "https://www.openai.com"

	scanner := NewConnectionScanner("/test/config.json")
	cfg := configparser.MCPServerConfig{
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
			assert.Equal(t, findings[0].RuleId, "tls-version-below-1.3")
			assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_MEDIUM)
			assert.Equal(t, findings[0].Tool, "connection-scanner")
			assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
			assert.Equal(t, findings[0].McpServerName, "test-server")
			assert.Equal(t, findings[0].File, "/test/config.json")
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
	cfg := configparser.MCPServerConfig{
		Name: "test-server",
		URL:  &invalidURL,
	}

	findings, err := scanner.checkCertificate(cfg)
	assert.Nil(t, err)
	t.Logf("Test connection error: %v", err)
	assert.Equal(t, 1, len(findings), fmt.Sprintf("Test connection error: expected 1 findings, got %d", len(findings)))
	assert.Equal(t, findings[0].RuleId, "connenction-failed-no-response")
	assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_CRITICAL)
	assert.Equal(t, findings[0].Tool, "connection-scanner")
	assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
	assert.Equal(t, findings[0].McpServerName, "test-server")
	assert.Equal(t, findings[0].File, "/test/config.json")
}

func TestDetectIdentityControl(t *testing.T) {
	t.Run("Test Asana MCP server", func(t *testing.T) {
		url := "https://mcp.asana.com/sse"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := configparser.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, findings[0].RuleId, "oauth-flow-detected")
		assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_LOW)
		assert.Equal(t, findings[0].Tool, "connection-scanner")
		assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
		assert.Equal(t, findings[0].McpServerName, "test-server")
		assert.Equal(t, findings[0].File, "/test/config.json")
	})

	t.Run("Test Supabase MCP server", func(t *testing.T) {
		url := "https://mcp.supabase.com/mcp"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := configparser.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, findings[0].RuleId, "oauth-flow-detected")
		assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_LOW)
		assert.Equal(t, findings[0].Tool, "connection-scanner")
		assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
		assert.Equal(t, findings[0].McpServerName, "test-server")
		assert.Equal(t, findings[0].File, "/test/config.json")
	})

	t.Run("Test No authentication", func(t *testing.T) {
		url := "https://www.google.com"
		scanner := NewConnectionScanner("/test/config.json")
		cfg := configparser.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.detectIdentityControl(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test detect identity control: expected 1 findings, got %d", len(findings)))
		assert.Equal(t, findings[0].RuleId, "no-authentication")
		assert.Equal(t, findings[0].Severity, proto.RiskSeverity_RISK_SEVERITY_HIGH)
		assert.Equal(t, findings[0].Tool, "connection-scanner")
		assert.Equal(t, findings[0].Type, proto.FindingType_FINDING_TYPE_CONNECTION)
		assert.Equal(t, findings[0].McpServerName, "test-server")
		assert.Equal(t, findings[0].File, "/test/config.json")
	})
}
