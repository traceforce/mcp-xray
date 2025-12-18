package configscan

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

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
		assert.Contains(t, findings[0].Message, "expired", "Error message should mention certificate is expired")
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
		assert.Contains(t, findings[0].Message, "authority", "Error message should mention certificate authority issue")
	})

	t.Run("Wrong host TLS certificate (hostname mismatch)", func(t *testing.T) {
		url := "https://wrong.host.badssl.com/"
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test wrong host certificate: expected 1 finding, got %d", len(findings)))
		assert.Equal(t, "invalid-certificate", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
		assert.Contains(t, findings[0].Message, "wrong.host.badssl.com", "Error message should mention the hostname")
	})

	t.Run("Self-signed TLS certificate", func(t *testing.T) {
		url := "https://self-signed.badssl.com/"
		cfg := libmcp.MCPServerConfig{
			Name: "test-server",
			URL:  &url,
		}
		findings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Test self-signed certificate: expected 1 finding, got %d", len(findings)))
		assert.Equal(t, "invalid-certificate", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
		assert.Contains(t, findings[0].Message, "authority", "Error message should mention certificate authority issue for self-signed cert")
	})
}

func TestCheckTLSVersion_WithInvalidCert(t *testing.T) {
	// Test that TLS version detection works even with invalid certificates
	// because checkTLSVersion uses InsecureSkipVerify
	url := "https://expired.badssl.com/"

	scanner := NewConnectionScanner("/test/config.json")
	cfg := libmcp.MCPServerConfig{
		Name: "test-server",
		URL:  &url,
	}

	t.Run("TLS version detection with expired cert", func(t *testing.T) {
		// First verify the cert is indeed invalid
		certFindings, err := scanner.checkCertificate(cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(certFindings), "Should detect certificate error")
		assert.Equal(t, "invalid-certificate", certFindings[0].RuleId)

		// But TLS version check should still work with InsecureSkipVerify
		// expired.badssl.com supports TLS 1.2 and 1.3
		findings12, err := scanner.checkTLSVersion(tls.VersionTLS12, cfg)
		assert.Nil(t, err)
		t.Logf("TLS 1.2 findings: %d", len(findings12))

		findings13, err := scanner.checkTLSVersion(tls.VersionTLS13, cfg)
		assert.Nil(t, err)
		t.Logf("TLS 1.3 findings: %d", len(findings13))

		// At least one of them should succeed (detect TLS version despite cert error)
		assert.True(t, len(findings12) > 0 || len(findings13) > 0,
			"Should be able to detect TLS version even with invalid certificate")
	})
}

func TestCheckTLSVersion_WithTLS(t *testing.T) {
	url := "https://mcp.asana.com/mcp"

	scanner := NewConnectionScanner("/test/config.json")
	cfg := libmcp.MCPServerConfig{
		Name: "test-server",
		URL:  &url,
	}

	t.Run("TLS 1.0", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS10, cfg)
		assert.Nil(t, err)
		// Most modern servers don't support TLS 1.0, so expect 0 findings
		assert.Equal(t, 0, len(findings), fmt.Sprintf("Test TLS 1.0: expected 0 finding, got %d", len(findings)))
		if len(findings) > 0 {
			assert.Equal(t, "tls-version-1.0-detected", findings[0].RuleId)
			assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
			t.Logf("Test TLS 1.0: %+v", findings)
		}
	})

	t.Run("TLS 1.1", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS11, cfg)
		assert.Nil(t, err)
		// Most modern servers don't support TLS 1.1, so expect 0 findings
		assert.Equal(t, 0, len(findings), fmt.Sprintf("Test TLS 1.1: expected 0 finding, got %d", len(findings)))
		if len(findings) > 0 {
			assert.Equal(t, "tls-version-1.1-detected", findings[0].RuleId)
			assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
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

func TestCheckTLSVersion_ConnectionError(t *testing.T) {
	scanner := NewConnectionScanner("/test/config.json")
	invalidURL := "https://invalid-domain-that-does-not-exist-12345.com"
	cfg := libmcp.MCPServerConfig{
		Name: "test-server",
		URL:  &invalidURL,
	}

	t.Run("Connection error during TLS version check", func(t *testing.T) {
		findings, err := scanner.checkTLSVersion(tls.VersionTLS13, cfg)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(findings), fmt.Sprintf("Expected 1 finding for connection error, got %d", len(findings)))
		assert.Equal(t, "tls-version-check-connection-error", findings[0].RuleId)
		assert.Equal(t, proto.RiskSeverity_RISK_SEVERITY_CRITICAL, findings[0].Severity)
		assert.Equal(t, "connection-scanner", findings[0].Tool)
		assert.Equal(t, proto.FindingType_FINDING_TYPE_CONNECTION, findings[0].Type)
		assert.Equal(t, "test-server", findings[0].McpServerName)
		assert.Equal(t, "/test/config.json", findings[0].File)
		assert.Contains(t, findings[0].Message, "Failed to connect")
	})
}

func TestIsTLSProtocolError(t *testing.T) {
	t.Run("Remote TLS alert", func(t *testing.T) {
		// Test with a server that sends TLS alert for unsupported version
		url := "https://mcp.asana.com/mcp"
		
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		}
		
		_, err := client.Get(url)
		assert.NotNil(t, err, "Should get error for TLS 1.0 to modern server")
		
		// Verify error structure
		var opErr *net.OpError
		assert.True(t, errors.As(err, &opErr), "Error should be net.OpError")
		assert.Equal(t, remoteErrorOp, opErr.Op, "Op should be 'remote error'")
		
		assert.True(t, isTLSProtocolError(err), "Should detect remote TLS alert as protocol error")
	})
	
	t.Run("Unsupported protocol version", func(t *testing.T) {
		// Test with client rejecting server's version choice
		url := "https://tls-v1-0.badssl.com:1010"
		
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		}
		
		_, err := client.Get(url)
		assert.NotNil(t, err, "Should get error for TLS 1.2 client to TLS 1.0 server")
		
		// Verify error contains the unsupported version message
		assert.Contains(t, err.Error(), unsupportedVersionErrorMsg, "Error should contain 'unsupported protocol version'")
		
		assert.True(t, isTLSProtocolError(err), "Should detect unsupported version as protocol error")
	})
	
	t.Run("Connection reset", func(t *testing.T) {
		// Test with server that resets connection for old TLS versions
		url := "https://tls-v1-2.badssl.com:1012"
		
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		}
		
		_, err := client.Get(url)
		assert.NotNil(t, err, "Should get error for TLS 1.0 client to TLS 1.2-only server")
		
		// Verify error structure
		var opErr *net.OpError
		assert.True(t, errors.As(err, &opErr), "Error should be net.OpError")
		assert.Equal(t, readOp, opErr.Op, "Op should be 'read'")
		
		var errno syscall.Errno
		assert.True(t, errors.As(opErr.Err, &errno), "Inner error should be syscall.Errno")
		assert.Equal(t, syscall.ECONNRESET, errno, "Should be ECONNRESET")
		
		assert.True(t, isTLSProtocolError(err), "Should detect connection reset as protocol error")
	})
	
	t.Run("Network error - DNS", func(t *testing.T) {
		// Test with DNS failure - should NOT be protocol error
		url := "https://invalid-domain-that-does-not-exist-12345.com"
		
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		}
		
		_, err := client.Get(url)
		assert.NotNil(t, err, "Should get DNS error")
		
		// Verify error structure - should be dial error, not read or remote error
		var opErr *net.OpError
		assert.True(t, errors.As(err, &opErr), "Error should be net.OpError")
		assert.Equal(t, "dial", opErr.Op, "Op should be 'dial'")
		
		assert.False(t, isTLSProtocolError(err), "Should NOT detect DNS error as protocol error")
	})
	
	t.Run("Nil error", func(t *testing.T) {
		assert.False(t, isTLSProtocolError(nil), "Nil error should not be protocol error")
	})
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
