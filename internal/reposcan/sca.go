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
	recursiveRoots, shallowRoots, err := splitScanRoots(s.repoPath, s.config)
	if err != nil {
		return nil, fmt.Errorf("osv scan failed to enumerate scan roots: %w", err)
	}

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
			// A directory with nothing OSV understands (e.g. a pure
			// container directory with no manifest of its own) is expected
			// once a scan is split across several roots -- most roots won't
			// have a manifest directly inside them. Only surfaced as
			// ErrUnsupportedInput below if EVERY group reports it, matching
			// the original single-call behavior where it meant the whole
			// input had nothing OSV could scan.
			unsupported++
			return nil
		}
		log.Printf("scan error: %v", callErr)
		return fmt.Errorf("osv scan failed: %w", callErr)
	}

	// Two groups because osv-scanner's Recursive flag applies to an entire
	// ScannerActions call, not per-path: a directory with an excluded
	// subdirectory can't be scanned recursively (that would pull the
	// exclusion back in) but must still have its own direct files covered,
	// so it is scanned non-recursively here while its clean children are
	// scanned recursively in the other group.
	if err := scanGroup(recursiveRoots, true); err != nil {
		return nil, err
	}
	if err := scanGroup(shallowRoots, false); err != nil {
		return nil, err
	}
	if calls == 0 {
		return nil, nil // the entire root is excluded; nothing to scan
	}
	if unsupported == calls {
		return nil, fmt.Errorf("%w: no packages found in scan", ErrUnsupportedInput)
	}

	// Normalize the results into a list of Findings
	findings := FromOSV(combined)
	fmt.Printf("Found %d vulnerabilities\n", len(findings))

	return findings, nil
}

// runOSVScan invokes osv-scanner over dirs and treats
// osvscanner.ErrVulnerabilitiesFound as success: DoScan computes it from the
// already-populated results purely to signal "there's something here" (the
// same convention the osv-scanner CLI uses via exit code 1), returning it
// alongside the real, valid results. Treating it as fatal would discard
// every genuine finding and abort the scan on the one input a security
// scanner exists to catch.
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

// splitScanRoots partitions root into the directory paths osv-scanner should
// be given so that cfg.ExcludedDirs is actually honored -- osv-scanner has no
// "recurse except these subdirectories" option, so exclusion has to happen
// at the directory-selection level instead, exactly like SASTScanner and
// SecretsScanner already exclude via cfg.ShouldExclude during their own
// filepath.Walk. This never tries to enumerate manifest/lockfile files
// itself (that list is necessarily incomplete -- see the comment on
// manifestAndLockfilePatterns in targetresolve); it only ever decides
// directory BOUNDARIES, and osv-scanner still does its own full,
// ecosystem-agnostic extractor walk inside every directory it's handed.
//
// recursiveRoots are subtrees with no exclusion anywhere inside them, safe
// to scan with Recursive:true as a single unit. shallowRoots are directories
// that contain an excluded child: their own direct files must still be
// scanned (a workspace's root manifest, say), but only non-recursively,
// since a recursive scan of the directory itself would pull the excluded
// child back in. Each excluded child's non-excluded siblings are evaluated
// independently and may themselves land in either list.
func splitScanRoots(root string, cfg *Config) (recursiveRoots, shallowRoots []string, err error) {
	if cfg.ShouldExclude(root) {
		return nil, nil, nil
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		// Root itself is unreadable/not a directory: let osv-scanner's own
		// os.Stat surface the real error rather than masking it here.
		return []string{root}, nil, nil
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

	// Recurse into every surviving child first: an exclusion arbitrarily
	// deep inside an otherwise-unremarkable child still means root can't be
	// scanned as one clean recursive unit, so this has to be known before
	// root's own case can be decided -- checking only root's immediate
	// children would miss any exclusion below the first level.
	for _, child := range childDirs {
		childRecursive, childShallow, err := splitScanRoots(child, cfg)
		if err != nil {
			return nil, nil, err
		}
		recursiveRoots = append(recursiveRoots, childRecursive...)
		shallowRoots = append(shallowRoots, childShallow...)
	}

	if !directlyPruned && len(shallowRoots) == 0 {
		// No exclusion directly among root's children, and the recursion
		// above found none deeper either: root is one clean subtree, and
		// whatever accumulated into recursiveRoots so far (nothing, since a
		// clean child always returns itself alone) is moot -- discard it in
		// favor of the single, cheaper root entry.
		return []string{root}, nil, nil
	}

	// An exclusion exists somewhere under root (directly, or discovered by
	// the recursion above). root's own direct files -- if any -- still need
	// to be scanned, but only non-recursively: a recursive entry for root
	// itself would pull the exclusion straight back in.
	shallowRoots = append(shallowRoots, root)
	return recursiveRoots, shallowRoots, nil
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
