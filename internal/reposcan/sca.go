package reposcan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"mcpxray/proto"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	cvss "github.com/pandatix/go-cvss/31"
)

// ErrUnsupportedInput distinguishes a valid scan invocation with no
// dependency input understood by OSV from an actual scanner failure.
var ErrUnsupportedInput = errors.New("unsupported SCA input")

// IsUnsupportedScanError reports whether err means there was nothing to scan.
func IsUnsupportedScanError(err error) bool { return errors.Is(err, ErrUnsupportedInput) }

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

func (s *SCAScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
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

// scanUnit runs SCA over a target scan's unit: the scan root minus the
// unit's ExcludedDirs (other targets' trees). Like Scan it reads every
// dependency file osv-scanner finds there, ExcludedPaths included, so the
// units of a plan cover what a full-repository scan covers. Unlike Scan it
// reports a failed osv-scanner call, and ErrUnsupportedInput when there was
// no dependency input at all, so the unit's execution record is accurate.
func (s *SCAScanner) scanUnit() ([]*proto.Finding, error) {
	recursiveRoots, shallowRoots := s.unitScanRoots()

	var combined models.VulnerabilityResults
	calls, unsupported := 0, 0
	scanGroup := func(dirs []string, recursive bool) error {
		if len(dirs) == 0 {
			return nil
		}
		calls++
		results, callErr := runOSVScan(dirs, recursive)
		combined.Results = append(combined.Results, results.Results...)
		if callErr == nil {
			return nil
		}
		if isUnsupportedOSVInput(callErr) {
			// Many split roots hold no manifest of their own; the scan as a
			// whole is unsupported only when every group says so.
			unsupported++
			return nil
		}
		log.Printf("scan error: %v", callErr)
		return fmt.Errorf("osv scan failed: %w", callErr)
	}

	// Two calls, because osv-scanner's Recursive flag applies to a whole
	// call rather than to each path (see splitScanRoots).
	if err := scanGroup(recursiveRoots, true); err != nil {
		return nil, err
	}
	if err := scanGroup(shallowRoots, false); err != nil {
		return nil, err
	}
	if unsupported == calls {
		return nil, fmt.Errorf("%w: no packages found in scan", ErrUnsupportedInput)
	}

	// Normalize the results into a list of Findings
	findings := FromOSV(combined)
	fmt.Printf("Found %d vulnerabilities\n", len(findings))

	return findings, nil
}

// unitScanRoots splits the scan root for scanUnit, leaving out only the
// unit's ExcludedDirs.
func (s *SCAScanner) unitScanRoots() (recursiveRoots, shallowRoots []string) {
	return splitScanRoots(s.repoPath, &Config{Root: s.config.Root, ExcludedDirs: s.config.ExcludedDirs})
}

// ScanRootOwnFiles runs SCA over root's own files, without descending into
// any subdirectory. It checks a workspace's shared root lockfile for targets
// that have none of their own, without rescanning other targets'
// directories.
func ScanRootOwnFiles(root string) ([]*proto.Finding, error) {
	results, err := runOSVScan([]string{root}, false)
	if err != nil {
		if isUnsupportedOSVInput(err) {
			return nil, fmt.Errorf("%w: no packages found in scan", ErrUnsupportedInput)
		}
		return nil, fmt.Errorf("osv scan failed: %w", err)
	}
	return FromOSV(results), nil
}

// runOSVScan invokes osv-scanner over dirs. osvscanner.ErrVulnerabilitiesFound
// is success: DoScan returns it alongside complete results whenever it
// finds a vulnerability (the CLI's exit code 1).
func runOSVScan(dirs []string, recursive bool) (models.VulnerabilityResults, error) {
	results, err := osvscanner.DoScan(osvscanner.ScannerActions{
		DirectoryPaths: dirs,
		Recursive:      recursive,

		// Optional: enable call/reachability analysis per ecosystem
		// Example keys include "npm", "pypi", "go" (see osv-scanner docs)
		// CallAnalysisStates: map[string]bool{"go": true, "npm": true, "pypi": true},
	})
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return results, err
	}
	return results, nil
}

func isUnsupportedOSVInput(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no packages found in scan")
}

// splitScanRoots picks the directories to hand osv-scanner so that cfg's
// exclusions are honored: osv-scanner cannot recurse "except these
// subdirectories", so exclusion happens by choosing directories, the way the
// SAST and secrets scanners skip excluded paths during their walk. Which
// files are manifests is left entirely to osv-scanner.
//
// recursiveRoots are subtrees with no exclusion anywhere inside them.
// shallowRoots are directories with an excluded descendant: their own files
// (a workspace's root manifest, say) are scanned non-recursively, since a
// recursive scan would pull the excluded descendant back in.
func splitScanRoots(root string, cfg *Config) (recursiveRoots, shallowRoots []string) {
	if cfg.ShouldExclude(root) {
		return nil, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		// Let osv-scanner report why root cannot be read.
		return []string{root}, nil
	}

	var childDirs []string
	directlyPruned := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child := filepath.Join(root, entry.Name())
		if cfg.ShouldExclude(child) {
			directlyPruned = true
			continue
		}
		childDirs = append(childDirs, child)
	}

	// An exclusion at any depth below a child decides root's case too.
	for _, child := range childDirs {
		childRecursive, childShallow := splitScanRoots(child, cfg)
		recursiveRoots = append(recursiveRoots, childRecursive...)
		shallowRoots = append(shallowRoots, childShallow...)
	}

	if !directlyPruned && len(shallowRoots) == 0 {
		// Nothing below root is excluded: scan it as one subtree.
		return []string{root}, nil
	}
	shallowRoots = append(shallowRoots, root)
	return recursiveRoots, shallowRoots
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
func FromOSV(results models.VulnerabilityResults) []*proto.Finding {
	out := []*proto.Finding{}

	for _, r := range results.Results {
		for _, pkg := range r.Packages {
			pkgName := pkg.Package.Name
			pkgVer := pkg.Package.Version

			for _, vuln := range pkg.Vulnerabilities {
				sev, _ := normalizeOSVSeverity(vuln)

				// Get file path from result source
				filePath := r.Source.Path

				out = append(out, &proto.Finding{
					Tool:     "osv",
					Type:     proto.FindingType_FINDING_TYPE_SCA,
					Severity: sev,
					RuleId:   vuln.GetId(),
					Title:    firstNonEmpty(vuln.GetSummary(), vuln.GetId()),
					Message:  firstNonEmpty(vuln.GetDetails(), vuln.GetSummary()),

					File:    filePath,
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
