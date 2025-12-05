package reposcan

import (
	"context"
	"fmt"
	"log"
	"strings"

	"SecureMCP/proto"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	cvss "github.com/pandatix/go-cvss/31"
)

type SCAScanner struct {
	repoPath string
	config   *Config
}

func NewSCAScanner(repoPath string, config *Config) *SCAScanner {
	return &SCAScanner{
		repoPath: repoPath,
		config:   config,
	}
}

func (s *SCAScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	actions := osvscanner.ScannerActions{
		// Scan this directory as "project source"
		DirectoryPaths: []string{s.repoPath},
		Recursive:      true,

		// Optional: enable call/reachability analysis per ecosystem
		// Example keys include "npm", "pypi", "go" (see osv-scanner docs)
		// CallAnalysisStates: map[string]bool{"go": true, "npm": true, "pypi": true},
	}

	results, err := osvscanner.DoScan(actions)
	if err != nil {
		// Note: DoScan may return a "vulnerabilities found" error in some configs,
		// so you might want to treat that as non-fatal and just read results.
		log.Printf("scan error: %v", err)
	}

	// Normalize the results into a list of Findings
	findings := FromOSV(results)
	fmt.Printf("Found %d vulnerabilities\n", len(findings))

	return findings, nil
}

// severityFromScore maps CVSS base score => unified bucket.
func severityFromScore(score float64) proto.RiskSeverity {
	switch {
	case score >= 9.0:
		return proto.RiskSeverity_RISK_SEVERITY_CRITICAL
	case score >= 7.0:
		return proto.RiskSeverity_RISK_SEVERITY_HIGH
	case score >= 4.0:
		return proto.RiskSeverity_RISK_SEVERITY_MEDIUM
	case score > 0.0:
		return proto.RiskSeverity_RISK_SEVERITY_LOW
	default:
		return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}

// normalizeLabel handles DB-provided coarse labels (like MODERATE).
func normalizeLabel(label string) proto.RiskSeverity {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return proto.RiskSeverity_RISK_SEVERITY_CRITICAL
	case "HIGH":
		return proto.RiskSeverity_RISK_SEVERITY_HIGH
	case "MEDIUM", "MODERATE":
		return proto.RiskSeverity_RISK_SEVERITY_MEDIUM
	case "LOW":
		return proto.RiskSeverity_RISK_SEVERITY_LOW
	default:
		return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}

// normalizeOSVSeverity reads an osvschema.Vulnerability and returns:
// - unified severity bucket
// - best CVSS base score found (0 if none)
func normalizeOSVSeverity(v *osvschema.Vulnerability) (proto.RiskSeverity, float64) {
	// 1) Prefer database_specific.severity if present (fast, consistent)
	if lbl, ok := getDatabaseSpecificString(v, "severity"); ok {
		return normalizeLabel(lbl), 0
	}

	// 2) Otherwise compute from any CVSS vectors in v.Severity[]
	bestScore := 0.0
	for _, s := range v.Severity {
		vec := strings.TrimSpace(s.Score)
		if vec == "" {
			continue
		}
		// Parse CVSS v3.x vector
		if strings.HasPrefix(strings.ToUpper(vec), "CVSS:3.") {
			parsed, err := cvss.ParseVector(vec)
			if err != nil {
				continue
			}
			score := parsed.BaseScore()
			if score > bestScore {
				bestScore = score
			}
		}
		// (If you later see CVSS:4.0, handle here similarly)
	}

	if bestScore > 0 {
		return severityFromScore(bestScore), bestScore
	}

	// 3) Fallback
	return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN, 0
}

// getDatabaseSpecificString safely pulls a string from v.DatabaseSpecific.Fields[key]
func getDatabaseSpecificString(v *osvschema.Vulnerability, key string) (string, bool) {
	if v.DatabaseSpecific == nil || v.DatabaseSpecific.Fields == nil {
		return "", false
	}
	f, ok := v.DatabaseSpecific.Fields[key]
	if !ok || f == nil || f.GetStringValue() == "" {
		return "", false
	}
	// osvschema uses protobuf-like Value; string_value is what we want
	if sv := f.GetStringValue(); sv != "" {
		return sv, true
	}
	return "", false
}

// FromOSV converts osv-scanner results into unified Finding objects.
func FromOSV(results models.VulnerabilityResults) []proto.Finding {
	out := []proto.Finding{}

	for _, r := range results.Results {
		for _, pkg := range r.Packages {
			pkgName := pkg.Package.Name
			pkgVer := pkg.Package.Version

			for _, vuln := range pkg.Vulnerabilities {
				sev, _ := normalizeOSVSeverity(vuln)

				out = append(out, proto.Finding{
					Tool:     "osv",
					Type:     proto.FindingType_FINDING_TYPE_SCA,
					Severity: sev,
					RuleId:   vuln.GetId(),
					Title:    firstNonEmpty(vuln.GetSummary(), vuln.GetId()),
					Message:  firstNonEmpty(vuln.GetDetails(), vuln.GetSummary()),

					Package: pkgName,
					Version: pkgVer,
					Fixed:   bestFixedVersion(vuln, pkgName),
				})
			}
		}
	}

	return out
}

// bestFixedVersion tries to find a fixed version for the given package
// from vuln.Affected ranges. Returns "" if not found.
func bestFixedVersion(v *osvschema.Vulnerability, pkgName string) string {
	for _, a := range v.Affected {
		if a.Package.Name != pkgName {
			continue
		}
		// Look for any "fixed" event in semver ranges
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed // first fixed is usually good enough
				}
			}
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
