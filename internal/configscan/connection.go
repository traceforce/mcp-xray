package configscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"mcpxray/internal/libmcp"
	"mcpxray/proto"
)

type ConnectionScanner struct {
	MCPconfigPath string
}

func NewConnectionScanner(configPath string) *ConnectionScanner {
	return &ConnectionScanner{
		MCPconfigPath: configPath,
	}
}

// For HTTP MCP servers, scan for authentication vulnerabilities.
// For STDIO MCP servers, this part will be skipped.
func (s *ConnectionScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	// Parse configPath
	servers, err := libmcp.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Connection scanner scanning %d MCP servers\n", len(servers))

	findings := []*proto.Finding{}
	for _, server := range servers {
		fmt.Printf("Scanning MCP Server %+v\n", server.RawJSON)
		classification := libmcp.ClassifyTransport(server)
		switch classification {
		case proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP:
			results, err := s.ScanConnection(ctx, server)
			if err != nil {
				return nil, err
			}
			findings = append(findings, results...)
		case proto.MCPTransportType_MCP_TRANSPORT_TYPE_STDIO:
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "stdio-transport-detected",
				Title:         "STDIO transport detected",
				McpServerName: server.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server “%s” is configured to use a STDIO transport. MCP servers running locally with STDIO access may execute system commands, which can potentially cause damage to the local system. Ensure that such servers are trusted and run with appropriate safeguards and least-privilege permissions.", server.Name),
			})
		default:
			// Skip unknown transport
			continue
		}
	}

	fmt.Printf("Connection scanner found %d findings\n", len(findings))
	// Return findings
	return findings, nil
}

// isLocalhostOrLoopback checks if the given URL points to localhost or loopback address
func isLocalhostOrLoopback(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return false
	}

	return isLoopbackHost(host)
}

// isLoopbackHost returns true for localhost/127.x.x.x/[::1] and common loopback cases.
// Handles Docker hosts, .localhost domains, and unspecified addresses.
func isLoopbackHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || h == "ip6-localhost" || h == "host.docker.internal" || h == "gateway.docker.internal" {
		return true
	}
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return true
	}
	return false
}

const (
	remoteErrorOp              = "remote error"
	readOp                     = "read"
	unsupportedVersionErrorMsg = "unsupported protocol version"
)

// isCertificateError checks if error is a TLS certificate validation error
func isCertificateError(err error) bool {
	if err == nil {
		return false
	}

	// Check for x509 certificate errors (remote cert problems, not local system issues)
	var x509UnknownAuthErr x509.UnknownAuthorityError
	var x509CertInvalidErr x509.CertificateInvalidError
	var x509HostnameErr x509.HostnameError
	var x509InsecureAlgErr x509.InsecureAlgorithmError
	var x509ConstraintErr x509.ConstraintViolationError
	var x509UnhandledExtErr x509.UnhandledCriticalExtension

	return errors.As(err, &x509UnknownAuthErr) ||
		errors.As(err, &x509CertInvalidErr) ||
		errors.As(err, &x509HostnameErr) ||
		errors.As(err, &x509InsecureAlgErr) ||
		errors.As(err, &x509ConstraintErr) ||
		errors.As(err, &x509UnhandledExtErr)
}

// isTLSProtocolError checks if an error is a TLS protocol error (version not supported)
// as opposed to other errors (network, timeout, connection refused, etc.)
func isTLSProtocolError(err error) bool {
	if err == nil {
		return false
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Server sends TLS alert (e.g., handshake failure, protocol version not supported)
		if opErr.Op == remoteErrorOp {
			return true
		}

		// Connection reset during handshake - common when server rejects old TLS versions
		// Modern servers (nginx/OpenSSL) often send TCP RST instead of TLS alert
		if opErr.Op == readOp {
			var errno syscall.Errno
			if errors.As(opErr.Err, &errno) && errno == syscall.ECONNRESET {
				return true
			}
		}
	}

	// Client-side rejection when server selects unsupported protocol version
	if strings.Contains(err.Error(), unsupportedVersionErrorMsg) {
		return true
	}

	return false
}

func (s *ConnectionScanner) ScanConnection(ctx context.Context, cfg libmcp.MCPServerConfig) ([]*proto.Finding, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("URL is not set")
	}
	urlStr := *cfg.URL

	// Report localhost/loopback addresses as medium risk
	if isLocalhostOrLoopback(urlStr) {
		return []*proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "localhost-loopback-detection",
				Title:         "MCP server URL points to localhost or loopback address. A local service can potentially be exploited by a remote attacker.",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is configured with a URL pointing to localhost or a loopback address (%s). This configuration exposes the service to potential exploitation by remote attackers who may gain access to the local system. Consider using a properly secured remote endpoint with authentication and encryption instead.", cfg.Name, urlStr),
			},
		}, nil
	}

	var allFindings []*proto.Finding

	// Perform certificate checks. All errors found are critical findings.
	findings, err := s.checkCertificate(cfg)
	if err != nil {
		return allFindings, err
	}
	allFindings = append(allFindings, findings...)

	// Always perform TLS version checks regardless of certificate status.
	// TLS version can still be determined even when certificate is invalid because
	// checkTLSVersion uses InsecureSkipVerify to test protocol support independently.
	for _, tlsVersion := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		findings, err := s.checkTLSVersion(tlsVersion, cfg)
		if err != nil {
			return allFindings, err
		}
		if len(findings) > 0 {
			// Report the first finding to reduce redundancy.
			allFindings = append(allFindings, findings...)
			break
		}
	}

	// Detect the authentication method used by the MCP server.
	findings, err = s.detectIdentityControl(cfg)
	if err != nil {
		return allFindings, err
	}
	allFindings = append(allFindings, findings...)

	return allFindings, nil
}

func (s *ConnectionScanner) checkCertificate(cfg libmcp.MCPServerConfig) ([]*proto.Finding, error) {
	var findings []*proto.Finding
	if cfg.URL == nil {
		return nil, fmt.Errorf("URL is not set")
	}
	urlStr := *cfg.URL

	// Create custom transport for Connection checks. Force the TLS version to the specified versions.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS11,
			MaxVersion: tls.VersionTLS13,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Make request to check Connection
	resp, err := client.Get(urlStr)
	if err != nil {
		fmt.Printf("Http error: %s, response: %+v\n", err.Error(), resp)
		if isCertificateError(err) {
			return []*proto.Finding{
				{
					Tool:          "connection-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
					RuleId:        "invalid-certificate",
					Title:         "Invalid TLS certificate",
					McpServerName: cfg.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("The MCP server '%s' has an invalid or untrusted TLS certificate. Connection to %s failed with certificate error: %s.", cfg.Name, urlStr, err.Error()),
				},
			}, nil
		} else if resp == nil {
			return []*proto.Finding{
				{
					Tool:          "connection-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
					RuleId:        "connection-failed-no-response",
					Title:         "Connection failed - no response",
					McpServerName: cfg.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("Failed to connect to MCP server %s. No response received.", urlStr),
				},
			}, nil
		} else {
			// Fall through for futher analysis on the response
		}
	}
	defer resp.Body.Close()

	// Check TLS version
	fmt.Printf("Response authentication header: %+v\n", resp.Header.Get("WWW-Authenticate"))
	if resp.TLS != nil {
		// Log the TLS version as we'll perform further checks on the TLS version later.
		fmt.Printf("resp.TLS type: %T, value: %+v\n", resp.TLS, resp.TLS.Version)
	} else {
		findings = append(findings, &proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
			RuleId:        "no-tls-certificate",
			Title:         "No TLS certificate found in connection response",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server '%s' at %s is not using TLS encryption. All communication is unencrypted and vulnerable to interception and man-in-the-middle attacks. This is a critical security issue. Please configure the server to use HTTPS with a valid TLS certificate.", cfg.Name, urlStr),
		})
	}

	return findings, nil
}

// checkTLSVersion checks if the server supports the specified TLS version.
// For highest security, the MCP server should only support the highest version available and never anything below 1.2.
func (s *ConnectionScanner) checkTLSVersion(tlsVersion uint16, cfg libmcp.MCPServerConfig) ([]*proto.Finding, error) {
	var findings []*proto.Finding
	if cfg.URL == nil {
		return nil, fmt.Errorf("URL is not set")
	}
	urlStr := *cfg.URL

	// Create custom transport for Connection checks. Force the TLS version to the specified version.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tlsVersion,
			MaxVersion:         tlsVersion,
			InsecureSkipVerify: true, // Skip cert validation - we're testing protocol support, not cert validity
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Make request to check Connection
	resp, err := client.Get(urlStr)
	if err != nil {
		fmt.Printf("Http error: %s\n", err.Error())
		// Check if this is NOT a TLS protocol error (version not supported)
		if !isTLSProtocolError(err) {
			// Connection error - report as finding and stop checking other TLS versions
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "tls-version-check-connection-error",
				Title:         "Connection error during TLS version check",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("Failed to connect to MCP server '%s' at %s while checking TLS version support: %s", cfg.Name, urlStr, err.Error()),
			})
			return findings, nil
		}
		// TLS protocol error - version not supported, continue to next version
	}

	if resp == nil {
		// TLS version not supported (protocol error)
		// For tls version 1.1 and 1.2, we will not return a finding if the server does not support the version
		// as it's recommended to only support the highest version available.
		if tlsVersion == tls.VersionTLS13 {
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
				RuleId:        "tls-version-1.3-not-supported",
				Title:         "TLS version 1.3 is not supported",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s does not support TLS version 1.3 which has the highest security standard. Please upgrade to TLS 1.3 or higher.", cfg.Name, urlStr),
			})
		}
		return findings, nil
	}
	defer resp.Body.Close()

	// Check TLS version
	fmt.Printf("Response authentication header: %+v\n", resp.Header.Get("WWW-Authenticate"))
	if resp.TLS != nil {
		fmt.Printf("resp.TLS type: %T, value: %+v\n", resp.TLS, resp.TLS.Version)
		if resp.TLS.Version == tls.VersionTLS12 {
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "tls-version-1.2-detected",
				Title:         "Server accepts TLS 1.2",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s accepts TLS version 1.2. While TLS 1.2 is still secure, TLS 1.3 provides improved security and performance. Consider disabling TLS 1.2 support and only accepting TLS 1.3.", cfg.Name, urlStr),
			})
		} else if resp.TLS.Version == tls.VersionTLS11 {
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "tls-version-1.1-detected",
				Title:         "Server accepts TLS 1.1",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s accepts TLS version 1.1. This version is vulnerable to various attacks and has been deprecated. Disable TLS 1.1 support immediately and only accept TLS 1.3.", cfg.Name, urlStr),
			})
		} else if resp.TLS.Version == tls.VersionTLS10 {
			findings = append(findings, &proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "tls-version-1.0-detected",
				Title:         "Server accepts TLS 1.0",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s accepts TLS version 1.0. This version is vulnerable to BEAST, POODLE, and other attacks and has been deprecated. Disable TLS 1.0 support immediately and only accept TLS 1.3.", cfg.Name, urlStr),
			})
		}
	}

	return findings, nil
}

// Detect the authentication method used by the MCP server.
func (s *ConnectionScanner) detectIdentityControl(cfg libmcp.MCPServerConfig) ([]*proto.Finding, error) {
	// Directly check HTTP authentication
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(*cfg.URL)
	if resp == nil || err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	fmt.Printf("Response status code: %d\n", resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		findings, err := s.checkOauthFlow(cfg)
		if err != nil {
			return nil, err
		}
		return findings, nil
	case http.StatusOK:
		return []*proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
				RuleId:        "no-authentication",
				Title:         "No authentication detected",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is not using any authentication. This is a high security risk. Please make sure the server does not have acces to any proprietary data or sensitive information.", cfg.Name),
			},
		}, nil
	default:
		// Do not report findings if we cannot find anything definitive.
		return []*proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
				RuleId:        "unexpected-status-code",
				Title:         "Unexpected status code detected",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' returned an unexpected status code on connection check: %d. This usually indicates a problem with the MCP server configuration or the MCP server implementation.", cfg.Name, resp.StatusCode),
			},
		}, nil
	}
}

func (s *ConnectionScanner) checkOauthFlow(cfg libmcp.MCPServerConfig) ([]*proto.Finding, error) {
	oauthConfig := libmcp.NewOAuthConfig(*cfg.URL)

	fmt.Println("1) Checking Protected Resource Metadata (PRM) is properly configured")
	prm, err := oauthConfig.DiscoverPRM()
	if err != nil {
		return []*proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "oauth-prm-not-configured",
				Title:         "OAuth PRM not configured",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is not using Protected Resource Metadata (PRM) for OAuth authentication. Oauth is the recommended authentication method for MCP servers. PRM is required to let clients automatically start the OAuth token exchange flow.", cfg.Name),
			},
		}, nil
	}

	fmt.Println("2) Discovering Authorization Server Metadata…")
	asmd, err := oauthConfig.DiscoverASMetadata(prm)
	if err != nil {
		return []*proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "oauth-asmd-not-configured",
				Title:         "OAuth ASMD not configured",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is not using Authorization Server Metadata (ASMD) for OAuth authentication. ASMD is required to let clients automatically discover an OAuth/OIDC server'sendpoints, supported flows, and security capabilities.", cfg.Name),
			},
		}, nil
	}

	// Evaluate the scopes supported by the MCP server.
	fmt.Printf("PRM OAuth scopes for %s: scope count %d\n", cfg.Name, len(prm.ScopesSupported))
	fmt.Printf("ASMD OAuth scopes for %s: scope count %d\n", cfg.Name, len(asmd.ScopesSupported))

	allFindings := []*proto.Finding{}
	if len(prm.ScopesSupported) == 0 {
		allFindings = append(allFindings, &proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:        "oauth-scopes-not-configured",
			Title:         "OAuth PRM scopes not configured",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server's protected resource metadata (RPM) '%s' is not using OAuth scopes for authentication. Without scopes, the MCP server cannot provide fine-grained access control to the resources it provides.", cfg.Name),
		})
	} else if len(prm.ScopesSupported) == 1 && strings.Contains(strings.ToLower(prm.ScopesSupported[0]), "default") {
		allFindings = append(allFindings, &proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:        "oauth-coarse-grained-scopes",
			Title:         "OAuth PRM scopes are coarse-grained",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server's protected resource metadata (RPM) '%s' is using a single default scope. Please consult with the MCP server owner for the correct scopes to use.", cfg.Name),
		})
	}

	if len(asmd.ScopesSupported) == 0 {
		allFindings = append(allFindings, &proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:        "oauth-scopes-not-configured",
			Title:         "OAuth ASMD scopes not configured",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server's authorization server metadata (ASMD) '%s' is not using OAuth scopes. Without scopes, the MCP server cannot provide fine-grained access control to the resources it provides.", cfg.Name),
		})
	} else if len(asmd.ScopesSupported) == 1 && strings.Contains(strings.ToLower(asmd.ScopesSupported[0]), "default") {
		allFindings = append(allFindings, &proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
			RuleId:        "oauth-coarse-grained-scopes",
			Title:         "OAuth ASMD scopes are coarse-grained",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server's authorization server metadata (ASMD) '%s' is using a single default scope. Please make sure to consult with the MCP server owner for the correct scopes to use.", cfg.Name),
		})
	}

	findings, err := s.checkOauthScopes(prm.ScopesSupported, cfg, "PRM")
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		allFindings = append(allFindings, findings...)
	}

	findings, err = s.checkOauthScopes(asmd.ScopesSupported, cfg, "ASMD")
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) > 0 {
		return allFindings, nil
	}

	// If no high severity findings, report a low severity finding to warn user that they must
	// apply least privilege to the scopes.
	return []*proto.Finding{
		{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_LOW,
			RuleId:        "oauth-flow-detected",
			Title:         "OAuth flow detected with valid PRM, ASMD endpoints and scopes",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The remote MCP server “%s” is configured to use OAuth authentication and exposes valid Protected Resource Metadata (PRM) and Authorization Server Metadata (ASMD) endpoints. Ensure that your MCP client application uses scopes restricted to the minimum set required for the MCP server's intended functionality, following the principle of least privilege.", cfg.Name),
		},
	}, nil
}

var (
	deleteKeywords = []string{"delete", "remove", "destroy", "drop", "purge", "erase", "revoke", "terminate", "cancel", "truncate", "unlink", "close"}
	writeKeywords  = []string{"create", "update", "write", "post", "put", "set", "add", "insert", "modify", "edit", "save", "upload", "replace", "rename", "move", "copy", "append", "patch", "grant", "send", "execute", "run", "publish", "deploy", "fork", "merge", "commit", "push", "assign", "approve", "enable", "activate", "configure", "triage", "label", "pin", "star", "clone", "new", "start", "navigate", "fill", "initiate"}
	readKeywords   = []string{"get", "list", "read", "fetch", "query", "search", "find", "retrieve", "view", "show", "download", "export", "scan", "watch", "select", "inspect", "monitor", "browse", "analyze", "review", "examine", "understand", "access", "track", "recommend", "suggest", "check", "compare", "verify"}
)

func checkStringSliceForKeywords(keywords []string, scope string) bool {
	normalizedScope := strings.ToLower(scope)
	for _, keyword := range keywords {
		if strings.Contains(normalizedScope, keyword) {
			fmt.Printf("Keyword %s found in scope %s\n", keyword, normalizedScope)
			return true
		}
	}
	return false
}

// checkOauthScopes checks if the scopes contain any delete, write, or read scopes. To reduce the amount of findings for
// a given MCP server, we will only report the most critical finding found.
func (s *ConnectionScanner) checkOauthScopes(scopes []string, cfg libmcp.MCPServerConfig, scopeType string) ([]*proto.Finding, error) {
	for _, scope := range scopes {
		normalizedScope := strings.ToLower(scope)
		if checkStringSliceForKeywords(deleteKeywords, normalizedScope) {
			return []*proto.Finding{
				{
					Tool:          "connection-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
					RuleId:        "oauth-delete-scope-detected",
					Title:         fmt.Sprintf("Delete scope detected in %s", scopeType),
					McpServerName: cfg.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("The MCP server '%s' scopes contains a delete scope. This is a high security risk. Please evaluate the scope and remove the scope during the MCP dynamic client registration if possible.", cfg.Name),
				},
			}, nil
		}
	}

	for _, scope := range scopes {
		normalizedScope := strings.ToLower(scope)
		if checkStringSliceForKeywords(writeKeywords, normalizedScope) {
			return []*proto.Finding{
				{
					Tool:          "connection-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
					RuleId:        "oauth-write-scope-detected",
					Title:         fmt.Sprintf("Write scope detected in %s", scopeType),
					McpServerName: cfg.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("The MCP server '%s' scopes contains a write scope. Please evaluate the scope and remove the scope during the MCP dynamic client registration if your application does not need it.", cfg.Name),
				},
			}, nil
		}
	}

	for _, scope := range scopes {
		normalizedScope := strings.ToLower(scope)
		if checkStringSliceForKeywords(readKeywords, normalizedScope) {
			return []*proto.Finding{
				{
					Tool:          "connection-scanner",
					Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
					Severity:      proto.RiskSeverity_RISK_SEVERITY_LOW,
					RuleId:        "oauth-read-scope-detected",
					Title:         fmt.Sprintf("Read scope detected in %s", scopeType),
					McpServerName: cfg.Name,
					File:          s.MCPconfigPath,
					Message:       fmt.Sprintf("The MCP server '%s' scopes contains a read scope. This is a low security risk. Please evaluate the scope and make sure the resource it reads is not sensitive or confidential.", cfg.Name),
				},
			}, nil
		}
	}
	return []*proto.Finding{}, nil
}
