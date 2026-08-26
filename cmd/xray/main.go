package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mcpxray/internal/aggregation"
	configscan "mcpxray/internal/configscan"
	"mcpxray/internal/pentest"
	"mcpxray/internal/report"
	reposcan "mcpxray/internal/reposcan"
	"mcpxray/internal/targetresolve"
	"mcpxray/proto"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rootCmd = &cobra.Command{
	Use:   "mcpxray",
	Short: "mcpxray - Security auditing tool for MCP applications",
	Long:  `A comprehensive security auditing tool designed to detect vulnerabilities and misconfigurations in applications using the Model Context Protocol (MCP).`,
}

func NewConfigScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config-scan [config-file]",
		Short: "Scan the configuration of the MCP server",
		Long:  "Scan the configuration of the MCP server. Use --scan-known-configs to scan all known config paths.",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			scanKnownConfigs, _ := cmd.Flags().GetBool("scan-known-configs")

			var configPaths []string

			if scanKnownConfigs {
				fmt.Println("Scanning all known MCP config paths")
				allPaths, err := configscan.GetAllKnownConfigPaths()
				if err != nil {
					fmt.Printf("Error getting known config paths: %v\n", err)
					os.Exit(1)
				}

				// Filter to only existing files
				for _, path := range allPaths {
					if fileInfo, err := os.Stat(path); err == nil && !fileInfo.IsDir() {
						configPaths = append(configPaths, path)
						fmt.Printf("Found config: %s\n", path)
					}
				}

				if len(configPaths) == 0 {
					fmt.Println("No known config files found")
					os.Exit(0)
				}
			} else {
				if len(args) == 0 {
					fmt.Println("Error: config file path is required when --scan-known-configs is not set")
					os.Exit(1)
				}
				configPath := args[0]

				// Validate that configPath is a file, not a directory
				fileInfo, err := os.Stat(configPath)
				if err != nil {
					if os.IsNotExist(err) {
						fmt.Printf("Error: config file does not exist: %s\n", configPath)
					} else {
						fmt.Printf("Error: cannot access config file: %s\n", err)
					}
					os.Exit(1)
				}
				if fileInfo.IsDir() {
					fmt.Printf("Error: config path must be a file, not a directory: %s\n", configPath)
					os.Exit(1)
				}

				configPaths = []string{configPath}
			}

			analyzerType, _ := cmd.Flags().GetString("analyzer-type")
			llmModel, _ := cmd.Flags().GetString("llm-model")
			fmt.Println("Analyzer type:", analyzerType)
			fmt.Println("LLM model:", llmModel)

			// Validate analyzer type
			if analyzerType != "token" && analyzerType != "llm" {
				fmt.Println("Error: analyzer-type must be either 'token' or 'llm'")
				os.Exit(1)
			}

			// Require llm-model only when analyzer-type is "llm"
			if analyzerType == "llm" && llmModel == "" {
				fmt.Println("Error: llm-model is required when analyzer-type is 'llm'")
				os.Exit(1)
			}

			if analyzerType == "token" && llmModel != "" {
				fmt.Println("Warning: llm-model is not used when analyzer-type is 'token'")
				llmModel = ""
			}

			toolsOutputFile, _ := cmd.Flags().GetString("tools-output")
			// Track if tools-output was user-specified before setting default
			toolsOutputUserSpecified := toolsOutputFile != ""
			// Set default tools output file if not provided
			if toolsOutputFile == "" {
				timestamp := time.Now().Format(time.RFC3339)
				toolsOutputFile = fmt.Sprintf("tools_summary_%s.json", strings.ReplaceAll(timestamp, ":", "-"))
			}

			// Validate environment variables if upload is requested (before scanning)
			upload, _ := cmd.Flags().GetBool("upload")
			shouldUpload := upload && !scanKnownConfigs
			if shouldUpload {
				if err := validateTraceforceEnv(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			// Scan all config paths and combine findings
			var allFindings []*proto.Finding
			ctx := context.Background()

			for _, configPath := range configPaths {
				fmt.Printf("\nScanning: %s\n", configPath)
				maxRetries, _ := cmd.Flags().GetInt("llm-max-retries")
				scanner, err := configscan.NewConfigScanner(configPath, analyzerType, llmModel, toolsOutputFile, maxRetries)
				if err != nil {
					fmt.Printf("Warning: Error creating config scanner for %s: %v\n", configPath, err)
					continue
				}
				findings, err := scanner.Scan(ctx)
				if err != nil {
					fmt.Printf("Warning: Error scanning configuration %s: %v\n", configPath, err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			cleanup, _ := cmd.Flags().GetBool("clean-up")
			// Track if output was user-specified
			outputUserSpecified := outputPath != ""
			// Use the actual config path as source name (when uploading, configPaths has exactly one element)
			sourceName := configPaths[0]
			actualOutputPath, err := writeFindings(allFindings, outputPath, "config-scan", shouldUpload, sourceName, toolsOutputFile, "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			// Cleanup generated files if requested and upload was successful
			if cleanup && shouldUpload {
				// Only clean up files that were auto-generated
				outputPathToClean := ""
				if !outputUserSpecified {
					outputPathToClean = actualOutputPath
				}
				toolsPathToClean := ""
				if !toolsOutputUserSpecified {
					toolsPathToClean = toolsOutputFile
				}
				if err := cleanupGeneratedFiles(outputPathToClean, toolsPathToClean, "", ""); err != nil {
					fmt.Printf("Error cleaning up files: %v\n", err)
					os.Exit(1)
				}
				if outputPathToClean != "" || toolsPathToClean != "" {
					fmt.Printf("Generated files cleaned up\n")
				}
			}
		},
	}
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings_<timestamp>.sarif.json)")
	cmd.Flags().String("analyzer-type", "token", "Analyzer type to use: 'token' or 'llm' (default: token)")
	cmd.Flags().String("llm-model", "", "LLM model to use for analysis (required when analyzer-type is 'llm')")
	cmd.Flags().Int("llm-max-retries", 3, "Maximum number of retries on transient LLM errors (rate limits, timeouts, 5xx), 0 = no retries")
	cmd.Flags().String("tools-output", "", "Output file path for tools JSON (default: tools_summary_<timestamp>.json)")
	cmd.Flags().Bool("scan-known-configs", false, "Scan all known MCP config paths")
	cmd.Flags().Bool("upload", false, "Upload the SARIF report to Traceforce Atlas endpoint (requires TRACEFORCE_CLIENT_ID, and TRACEFORCE_CLIENT_SECRET env vars)")
	cmd.Flags().Bool("clean-up", false, "Remove all generated files after successful upload (requires --upload)")
	return cmd
}

func NewRepoScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo-scan [repo-path]",
		Short: "Scan the repository of the MCP server",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scanning the repository of the MCP server")
			repoPath := "."
			if len(args) > 0 {
				repoPath = args[0]
			}

			maxFileSize, _ := cmd.Flags().GetInt64("max-file-size")
			excludedPaths, _ := cmd.Flags().GetStringArray("exclude-paths")
			useDefaultExcludes, _ := cmd.Flags().GetBool("use-default-excludes")
			enableCVE, _ := cmd.Flags().GetBool("cve")
			enableSecrets, _ := cmd.Flags().GetBool("secrets")
			enableSAST, _ := cmd.Flags().GetBool("sast")
			codeqlAllowBuild, _ := cmd.Flags().GetBool("codeql-allow-build")
			codeqlTimeout, _ := cmd.Flags().GetInt("codeql-timeout")

			// Base max-file-size/excludes/CodeQL settings, shared by every root
			// this command ends up scanning (one root in the legacy path, one
			// or more roots when a target-resolution target has resolved
			// shared components). Only Root differs per scan below.
			baseMaxFileSize := int64(10 * 1024 * 1024) // 10MB default
			if maxFileSize > 0 {
				baseMaxFileSize = maxFileSize
			}
			defaultConfig := reposcan.DefaultConfig()
			baseExcludes := []string{}
			if useDefaultExcludes {
				baseExcludes = append(baseExcludes, defaultConfig.ExcludedPaths...)
			}
			baseExcludes = append(baseExcludes, excludedPaths...)

			// Determine which scans to run
			// If no specific scan is enabled, run all (backward compatible)
			runAll := !enableCVE && !enableSecrets && !enableSAST
			runCVE := runAll || enableCVE
			runSecrets := runAll || enableSecrets
			runSAST := runAll || enableSAST

			// Validate environment variables if upload is requested (before scanning)
			upload, _ := cmd.Flags().GetBool("upload")
			if upload {
				if err := validateTraceforceEnv(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			ctx := context.Background()

			// runScanners runs every enabled scanner against root (scoped by
			// cfg) and merges their findings. Both the legacy single-root
			// path below and the target-resolution multi-root path call
			// this same function, so which scanners run and how never
			// diverges between the two -- only how many times, and against
			// which roots, this gets called differs.
			runScanners := func(root string, cfg *reposcan.Config) ([]*proto.Finding, error) {
				var findings []*proto.Finding
				if runCVE {
					f, err := reposcan.NewSCAScanner(root, cfg).Scan(ctx)
					if err != nil {
						if !reposcan.IsUnsupportedScanError(err) {
							return nil, fmt.Errorf("error running CVE scan: %w", err)
						}
					} else {
						findings = append(findings, f...)
					}
				}
				if runSecrets {
					f, err := reposcan.NewSecretsScanner(root, cfg).Scan(ctx)
					if err != nil {
						return nil, fmt.Errorf("error running secrets scan: %w", err)
					}
					findings = append(findings, f...)
				}
				if runSAST {
					f, err := reposcan.NewSASTScanner(root, cfg).Scan(ctx)
					if err != nil {
						return nil, fmt.Errorf("error running SAST scan: %w", err)
					}
					findings = append(findings, f...)
				}
				return findings, nil
			}

			outputPath, _ := cmd.Flags().GetString("output")
			outputDirs, _ := cmd.Flags().GetStringArray("output-dir")
			cleanup, _ := cmd.Flags().GetBool("clean-up")

			// runLegacyFullRepoScan is the exact original repo-scan behavior:
			// one scan of repoPath as a single root. Used both when
			// target-resolution was never requested, and as the fallback
			// when it was requested but found zero MCP server targets (there
			// is nothing to narrow the scope to).
			runLegacyFullRepoScan := func() {
				config := &reposcan.Config{MaxFileSize: baseMaxFileSize, Root: repoPath, ExcludedPaths: baseExcludes, CodeQLAllowBuild: codeqlAllowBuild, CodeQLTimeoutSec: codeqlTimeout}
				allFindings, err := runScanners(repoPath, config)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				sourceName := "repo-scan"
				if repoPath != "." {
					sourceName = filepath.Base(repoPath)
				}
				actualOutputPath, err := writeFindings(allFindings, outputPath, "repo-scan", upload, sourceName, "", "")
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				if cleanup && upload {
					if err := cleanupGeneratedFiles(actualOutputPath, "", "", ""); err != nil {
						fmt.Printf("Error cleaning up files: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("Generated files cleaned up\n")
				}
			}

			targetResolutionFlag, _ := cmd.Flags().GetBool("target-resolution")
			listTargets, _ := cmd.Flags().GetBool("list-targets")
			targetIDsFlag, _ := cmd.Flags().GetStringArray("target-id")
			allTargetsFlag, _ := cmd.Flags().GetBool("all-targets")
			includeRepoGlobalFlag, _ := cmd.Flags().GetBool("include-repo-global")
			explainScopeFlag, _ := cmd.Flags().GetBool("explain-scope")

			if !targetResolutionFlag && !listTargets && len(targetIDsFlag) == 0 && !allTargetsFlag && !includeRepoGlobalFlag && !explainScopeFlag {
				// Default behavior: identical to repo-scan before target
				// resolution existed -- the full repo is always scanned as
				// one unit here, regardless of what detection below finds.
				// Detection is best-effort and purely informational: a
				// resolve error or a slow/ambiguous repo never blocks or
				// changes the scan that follows.
				if resolution, resolveErr := targetresolve.Resolve(repoPath); resolveErr == nil && len(resolution.Targets) >= 2 {
					fmt.Printf("Detected %d MCP server targets in this repository. To scan them individually instead of the whole repo, rerun with --target-resolution --list-targets.\n", len(resolution.Targets))
				}
				runLegacyFullRepoScan()
				return
			}

			resolution, err := targetresolve.Resolve(repoPath)
			if err != nil {
				fmt.Println("Error resolving MCP targets:", err)
				os.Exit(1)
			}
			for _, w := range resolution.Warnings {
				fmt.Println("Warning:", w)
			}

			if listTargets {
				jsonOutput, _ := cmd.Flags().GetBool("json")
				if jsonOutput {
					data, marshalErr := targetresolve.ResolutionJSON(resolution)
					if marshalErr != nil {
						fmt.Println(marshalErr)
						os.Exit(1)
					}
					fmt.Println(string(data))
				} else {
					printDiscoveredTargets(resolution.Targets, resolution.Projects, resolution.RepoRoot)
				}
				return
			}

			targetFlag, _ := cmd.Flags().GetString("target")
			targetIDs, _ := cmd.Flags().GetStringArray("target-id")
			allTargets, _ := cmd.Flags().GetBool("all-targets")
			includeRepoGlobal, _ := cmd.Flags().GetBool("include-repo-global")
			explainScope, _ := cmd.Flags().GetBool("explain-scope")

			if len(resolution.Targets) == 0 {
				if explicitTargetRequested(targetFlag, targetIDs, allTargets) {
					fmt.Println("No requested MCP target was discovered; the repository has no discoverable MCP server targets to scan.")
					os.Exit(1)
				}
				fmt.Println("No MCP server detected; scanning the full repository")
				runLegacyFullRepoScan()
				return
			}

			if targetFlag != "" {
				for _, candidate := range resolution.Targets {
					if candidate.Name == targetFlag {
						targetIDs = append(targetIDs, candidate.ID)
						break
					}
				}
			}
			if len(targetIDs) == 0 && !allTargets {
				target, selectErr := selectTarget(resolution.Targets, resolution.Projects, resolution.RepoRoot, targetFlag)
				if selectErr != nil {
					fmt.Println(selectErr)
					os.Exit(1)
				}
				targetIDs = []string{target.ID}
			}
			plan, err := targetresolve.BuildScanPlan(resolution, targetresolve.PlanOptions{TargetIDs: targetIDs, AllTargets: allTargets, IncludeRepoGlobal: includeRepoGlobal, OutputPath: outputPath, OutputDirs: outputDirs})
			if err != nil {
				fmt.Println("Error building scan plan:", err)
				os.Exit(1)
			}
			fmt.Printf("Scanning %d target(s) across %d physical scan unit(s)\n", len(plan.SelectedTargets), len(plan.Units))
			if explainScope {
				data, marshalErr := targetresolve.ScanPlanJSON(plan)
				if marshalErr == nil {
					fmt.Println(string(data))
				}
			}

			var attributed []aggregation.AttributedFinding
			var scanFailures []string
			var executions []reposcan.ScannerExecution
			rawCountByTarget := make(map[string]int)
			for _, unit := range plan.Units {
				cfg := &reposcan.Config{MaxFileSize: baseMaxFileSize, Root: unit.Root, ExcludedPaths: baseExcludes, ExcludedDirs: unit.ExcludedDirs, CodeQLAllowBuild: codeqlAllowBuild, CodeQLTimeoutSec: codeqlTimeout}
				runUnitSCA := runCVE && (filepath.Clean(unit.Root) != filepath.Clean(resolution.RepoRoot) || hasDirectRelation(unit))
				inputSummary := fmt.Sprintf("root=%s manifests=%d lockfiles=%d files=%d", unit.RelativeRoot, len(unit.Manifests), len(unit.Lockfiles), len(unit.Files))
				detailed := reposcan.ScanDetailed(ctx, unit.Root, cfg, reposcan.ScannerSelection{SCA: runUnitSCA, Secrets: runSecrets, SAST: runSAST}, unit.ID, inputSummary)
				executions = append(executions, detailed.Executions...)
				for _, execution := range detailed.Executions {
					if execution.Status == reposcan.ScannerFailed {
						scanFailures = append(scanFailures, execution.Scanner+" on "+unit.ID+": "+execution.Error)
					}
				}
				for _, finding := range detailed.Findings {
					relPath := finding.File
					if rel, relErr := filepath.Rel(resolution.RepoRoot, finding.File); relErr == nil {
						relPath = filepath.ToSlash(rel)
					}
					fo := targetresolve.LookupFileOwnership(plan, relPath)
					execID := ""
					if finding.Tool != "" {
						for _, exec := range detailed.Executions {
							if exec.ScanUnitID == unit.ID && executionScannerMatches(exec.Scanner, finding.Tool) {
								execID = exec.ID
								break
							}
						}
					}
					af := aggregation.AttributedFinding{
						Finding:      finding,
						TargetIDs:    fo.TargetIDs,
						ComponentIDs: fo.ComponentIDs,
						ScanUnitID:   unit.ID,
						ExecutionID:  execID,
						Relation:     fo.Relation,
						Context:      fo.Context,
					}
					attributed = append(attributed, af)
					for _, tid := range fo.TargetIDs {
						rawCountByTarget[tid]++
					}
				}
			}
			if len(scanFailures) > 0 {
				fmt.Println("Scanner failures:", strings.Join(scanFailures, "; "))
				os.Exit(1)
			}
			aggregated := aggregation.Aggregate(resolution.RepoRoot, attributed)
			uniqueFindings := make([]*proto.Finding, 0, len(aggregated))
			properties := make([]map[string]interface{}, 0, len(aggregated))
			uniqueCountByTarget := make(map[string]int)
			for _, item := range aggregated {
				uniqueFindings = append(uniqueFindings, item.Finding)
				props := map[string]interface{}{
					"fingerprint":    item.Fingerprint,
					"rawCount":       item.RawCount,
					"duplicateCount": item.DuplicateCount,
					"targetIds":      item.TargetIDs,
					"componentIds":   item.ComponentIDs,
					"scanUnitIds":    item.ScanUnitIDs,
					"relations":      item.Relations,
					"context":        item.Contexts,
				}
				if len(item.RawInstances) > 0 {
					props["rawInstances"] = item.RawInstances
				}
				properties = append(properties, props)
				for _, tid := range item.TargetIDs {
					uniqueCountByTarget[tid]++
				}
			}

			targetSummaries := make([]targetresolve.TargetSummary, 0, len(plan.SelectedTargets))
			for _, target := range plan.SelectedTargets {
				var scanUnitIDs []string
				for _, unit := range plan.Units {
					for _, tid := range unit.TargetIDs {
						if tid == target.ID {
							scanUnitIDs = append(scanUnitIDs, unit.ID)
							break
						}
					}
				}
				targetSummaries = append(targetSummaries, targetresolve.TargetSummary{
					TargetID:       target.ID,
					Name:           target.Name,
					ProjectID:      target.Project.ID,
					ComponentID:    target.ComponentID,
					OwnershipRoot:  repoRelativeSlash(resolution.RepoRoot, target.Project.OwnershipRoot),
					ScanUnitIDs:    scanUnitIDs,
					RawFindings:    rawCountByTarget[target.ID],
					UniqueFindings: uniqueCountByTarget[target.ID],
				})
			}

			runProperties := map[string]interface{}{
				"targetSummaries": targetSummaries,
				"scanPlan":        targetresolve.StructuredScanPlan(plan),
				"executions":      executions,
			}

			if explainScope {
				diagnostics, marshalErr := json.MarshalIndent(map[string]interface{}{"scanPlan": targetresolve.StructuredScanPlan(plan), "executions": executions, "rawFindingCount": len(attributed), "uniqueFindingCount": len(aggregated), "duplicateFindingCount": len(attributed) - len(aggregated)}, "", "  ")
				if marshalErr == nil {
					fmt.Println(string(diagnostics))
				}
			}
			sarifBytes, err := report.GenerateSarifWithProperties(uniqueFindings, properties, resolution.RepoRoot, runProperties)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			actualOutputPath, err := writeSarifBytes(sarifBytes, outputPath, "repo-scan", upload, targetSourceName(plan), "", "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if cleanup && upload {
				if err := cleanupGeneratedFiles(actualOutputPath, "", "", ""); err != nil {
					fmt.Printf("Error cleaning up files: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("Generated files cleaned up\n")
			}
		},
	}
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings.sarif.json)")
	cmd.Flags().StringArray("output-dir", nil, "Configured MCP X-Ray output directory to exclude from scope (can be specified multiple times)")
	cmd.Flags().Int64("max-file-size", 0, "Maximum file size in bytes to scan (0 uses default: 10MB)")
	cmd.Flags().StringArrayP("exclude-paths", "e", []string{}, "Path pattern to exclude from scanning (can be specified multiple times)")
	cmd.Flags().Bool("use-default-excludes", true, "Use default exclude paths (e.g., node_modules, .git, etc.). By default, certain files and directories are excluded from scanning.")
	cmd.Flags().Bool("cve", false, "Run CVE/SCA scan (software composition analysis)")
	cmd.Flags().Bool("secrets", false, "Run secrets scan")
	cmd.Flags().Bool("sast", false, "Run SAST scan (static application security testing)")
	cmd.Flags().Bool("codeql-allow-build", false, "Allow CodeQL to build a Go database (runs the Go toolchain, which can execute build-time code; only for trusted repos)")
	cmd.Flags().Int("codeql-timeout", 0, "Per-language CodeQL budget in seconds, covering database create + analyze (0 = MCPXRAY_CODEQL_TIMEOUT, else 600). Raise for large repositories.")
	cmd.Flags().Bool("upload", false, "Upload the SARIF report to Traceforce Atlas endpoint (requires TRACEFORCE_CLIENT_ID, and TRACEFORCE_CLIENT_SECRET env vars)")
	cmd.Flags().Bool("clean-up", false, "Remove all generated files after successful upload (requires --upload)")
	cmd.Flags().Bool("target-resolution", false, "Detect MCP server(s) in the repository and scan only the selected one plus its resolved shared components, instead of the whole repository")
	cmd.Flags().String("target", "", "Name of the MCP target to scan when --target-resolution finds more than one (see --list-targets)")
	cmd.Flags().StringArray("target-id", nil, "Stable ID of an MCP target to scan (can be specified multiple times)")
	cmd.Flags().Bool("all-targets", false, "Scan all discovered MCP targets in one deduplicated plan")
	cmd.Flags().Bool("include-repo-global", false, "Include repository-global files once in the selected-target plan")
	cmd.Flags().Bool("explain-scope", false, "Print the structured scan scope and diagnostics")
	cmd.Flags().Bool("json", false, "Print structured JSON for --list-targets")
	cmd.Flags().Bool("list-targets", false, "Detect and print MCP server targets in the repository, then exit without scanning (implies --target-resolution)")
	return cmd
}

func targetSourceName(plan *targetresolve.ScanPlan) string {
	if len(plan.SelectedTargets) == 1 {
		return plan.SelectedTargets[0].ID
	}
	return fmt.Sprintf("%d-target-plan", len(plan.SelectedTargets))
}

func executionScannerMatches(executionScanner, findingTool string) bool {
	executionScanner = strings.ToLower(executionScanner)
	findingTool = strings.ToLower(findingTool)
	if executionScanner == findingTool {
		return true
	}
	switch executionScanner {
	case "osv":
		return findingTool == "osv-scanner" || findingTool == "sca"
	case "gitleaks":
		return findingTool == "gitleaks" || findingTool == "secrets"
	case "sast":
		return findingTool == "sast" || findingTool == "semgrep"
	}
	return false
}

func repoRelativeSlash(repoRoot, absPath string) string {
	if absPath == "" {
		return ""
	}
	if rel, err := filepath.Rel(repoRoot, absPath); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(absPath)
}

// explicitTargetRequested reports whether the user asked to scan a specific
// target selection (by name, by id, or all of them) rather than merely
// opting into target-resolution's informational/explain-scope machinery.
// When true and resolution finds zero targets, silently falling back to a
// full-repo scan would ignore the user's actual request instead of telling
// them it could not be satisfied.
func explicitTargetRequested(targetFlag string, targetIDs []string, allTargets bool) bool {
	return targetFlag != "" || len(targetIDs) > 0 || allTargets
}

func hasDirectRelation(unit *targetresolve.ScanUnit) bool {
	for _, relation := range unit.Relations {
		if relation == targetresolve.RelationDirect {
			return true
		}
	}
	return false
}

func NewPentestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pentest <config-file>",
		Short: "Run a pentest against the MCP servers defined in the configuration file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			configPath := args[0]
			llmModel, _ := cmd.Flags().GetString("llm-model")
			testPlanFile, _ := cmd.Flags().GetString("test-plan")
			testPlanDir, _ := cmd.Flags().GetString("test-directory")
			// Track if test-directory was user-specified before setting default
			testPlanDirUserSpecified := testPlanDir != ""

			// Validate that configPath is a file, not a directory
			fileInfo, err := os.Stat(configPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Printf("Error: config file does not exist: %s\n", configPath)
				} else {
					fmt.Printf("Error: cannot access config file: %s\n", err)
				}
				os.Exit(1)
			}
			if fileInfo.IsDir() {
				fmt.Printf("Error: config path must be a file, not a directory: %s\n", configPath)
				os.Exit(1)
			}

			// Validate test plan file if provided
			var testPlanPath string
			var isDirectory bool
			var testFilePath string
			// Track if test plan file was user-specified (via --test-plan)
			testPlanFileUserSpecified := testPlanFile != ""

			if testPlanFile != "" {
				// --test-plan: must be a file that exists
				testPlanInfo, err := os.Stat(testPlanFile)
				if err != nil {
					if os.IsNotExist(err) {
						fmt.Printf("Error: test plan file does not exist: %s\n", testPlanFile)
					} else {
						fmt.Printf("Error: cannot access test plan file: %s\n", err)
					}
					os.Exit(1)
				}
				if testPlanInfo.IsDir() {
					fmt.Printf("Error: --test-plan must be a file, not a directory: %s\n", testPlanFile)
					os.Exit(1)
				}
				isDirectory = false
				testPlanPath = testPlanFile
				testFilePath = testPlanFile
			} else {
				// --test-directory: use provided directory or default
				if testPlanDir == "" {
					// Use default directory - create it
					timestamp := time.Now().Format(time.RFC3339)
					timestamp = strings.ReplaceAll(timestamp, ":", "-")
					testPlanDir = fmt.Sprintf("pentest_plans_%s", timestamp)
					if err := os.MkdirAll(testPlanDir, 0755); err != nil {
						fmt.Printf("Error: failed to create default test plan directory: %v\n", err)
						os.Exit(1)
					}
				} else {
					// Directory was specified - validate that it exists
					testPlanInfo, err := os.Stat(testPlanDir)
					if err != nil {
						if os.IsNotExist(err) {
							fmt.Printf("Error: test plan directory does not exist: %s\n", testPlanDir)
							os.Exit(1)
						} else {
							fmt.Printf("Error: cannot access test plan directory: %s\n", err)
							os.Exit(1)
						}
					}
					if !testPlanInfo.IsDir() {
						fmt.Printf("Error: --test-directory must be a directory, not a file: %s\n", testPlanDir)
						os.Exit(1)
					}
				}
				isDirectory = true
				testPlanPath = testPlanDir
			}

			if llmModel == "" {
				fmt.Println("Error: llm-model is required for pentest.")
				os.Exit(1)
			}

			// Validate environment variables if upload is requested (before running pentest)
			upload, _ := cmd.Flags().GetBool("upload")
			if upload {
				if err := validateTraceforceEnv(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			// Create pentest tool
			maxRetries, _ := cmd.Flags().GetInt("llm-max-retries")
			pentestTool, err := pentest.NewPentestTool(configPath, llmModel, maxRetries)
			if err != nil {
				fmt.Printf("Error creating pentest tool: %v\n", err)
				os.Exit(1)
			}

			// Run pentest
			ctx := context.Background()
			findings, err := pentestTool.Pentest(ctx, testPlanPath)
			if err != nil {
				fmt.Printf("Error running pentest: %v\n", err)
				os.Exit(1)
			}

			// If using directory mode, always merge all per-tool test plans and write merged file
			if isDirectory {
				mergedTestPlan, err := mergeTestPlansFromDir(testPlanPath)
				if err != nil {
					fmt.Printf("Warning: failed to merge test plans: %v\n", err)
				} else if mergedTestPlan != "" {
					mergedFilePath := filepath.Join(testPlanPath, "merged_test_plan.yaml")
					if err := os.WriteFile(mergedFilePath, []byte(mergedTestPlan), 0644); err != nil {
						fmt.Printf("Warning: failed to write merged test plan: %v\n", err)
					} else {
						testFilePath = mergedFilePath
					}
				}
			}

			// Write findings to output file
			outputPath, _ := cmd.Flags().GetString("output")
			cleanup, _ := cmd.Flags().GetBool("clean-up")
			// Track if output was user-specified
			outputUserSpecified := outputPath != ""
			sourceName := configPath
			// Track test plan directory for cleanup (only if in directory mode and not user-specified)
			var testPlanDirPath string
			if isDirectory && !testPlanDirUserSpecified {
				testPlanDirPath = testPlanPath
			}
			actualOutputPath, err := writeFindings(findings, outputPath, "pentest", upload, sourceName, "", testFilePath)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			// Cleanup generated files if requested and upload was successful
			if cleanup && upload {
				// Only clean up files that were auto-generated
				outputPathToClean := ""
				if !outputUserSpecified {
					outputPathToClean = actualOutputPath
				}
				// Only clean up testFilePath if it was auto-generated (merged test plan), not if user-specified via --test-plan
				testFilePathToClean := ""
				if !testPlanFileUserSpecified && testFilePath != "" {
					testFilePathToClean = testFilePath
				}
				// testPlanDirPath is only set if directory was auto-generated
				if err := cleanupGeneratedFiles(outputPathToClean, "", testFilePathToClean, testPlanDirPath); err != nil {
					fmt.Printf("Error cleaning up files: %v\n", err)
					os.Exit(1)
				}
				if outputPathToClean != "" || testFilePathToClean != "" || testPlanDirPath != "" {
					fmt.Printf("Generated files cleaned up\n")
				}
			}
		},
	}
	cmd.Flags().String("llm-model", "", "LLM model to use for pentest plan generation (required)")
	cmd.Flags().Int("llm-max-retries", 3, "Maximum number of retries on transient LLM errors (rate limits, timeouts, 5xx), 0 = no retries")
	cmd.Flags().String("test-plan", "", "Test plan YAML file to use (must exist). If specified, uses this file for all servers.")
	cmd.Flags().String("test-directory", "", "Directory to store generated test plans (default: pentest_plans_<timestamp>). Must exist if specified.")
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings_<timestamp>.sarif.json)")
	cmd.Flags().Bool("upload", false, "Upload the SARIF report to Traceforce Atlas endpoint (requires TRACEFORCE_CLIENT_ID, and TRACEFORCE_CLIENT_SECRET env vars)")
	cmd.Flags().Bool("clean-up", false, "Remove all generated files after successful upload (requires --upload)")

	return cmd
}

func NewVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify findings from a SARIF file using an LLM to filter false positives",
		Long:  "Load findings from a SARIF file, run LLM-based verification, and write the verified findings to a new SARIF report. Requires --sarif and --llm-model.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			sarifPath, _ := cmd.Flags().GetString("sarif")
			llmModel, _ := cmd.Flags().GetString("llm-model")

			if sarifPath == "" {
				fmt.Println("Error: --sarif is required.")
				os.Exit(1)
			}
			if llmModel == "" {
				fmt.Println("Error: --llm-model is required.")
				os.Exit(1)
			}

			fileInfo, err := os.Stat(sarifPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Printf("Error: SARIF file does not exist: %s\n", sarifPath)
				} else {
					fmt.Printf("Error: cannot access SARIF file: %s\n", err)
				}
				os.Exit(1)
			}
			if fileInfo.IsDir() {
				fmt.Printf("Error: --sarif must be a file, not a directory: %s\n", sarifPath)
				os.Exit(1)
			}

			findings, err := pentest.ParseSarifToFindings(sarifPath)
			if err != nil {
				fmt.Printf("Error parsing SARIF file: %v\n", err)
				os.Exit(1)
			}

			maxRetries, _ := cmd.Flags().GetInt("llm-max-retries")
			verifyTool, err := pentest.NewVerifyTool("", llmModel, maxRetries)
			if err != nil {
				fmt.Printf("Error creating verify tool: %v\n", err)
				os.Exit(1)
			}

			ctx := context.Background()
			verifiedFindings, err := verifyTool.VerifyFindings(ctx, findings)
			if err != nil {
				fmt.Printf("Error verifying findings: %v\n", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			upload, _ := cmd.Flags().GetBool("upload")
			if upload {
				if err := validateTraceforceEnv(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			actualOutputPath, err := writeFindings(verifiedFindings, outputPath, "verify", upload, sarifPath, "", "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Verified findings written to %s\n", actualOutputPath)
		},
	}
	cmd.Flags().String("sarif", "", "Path to SARIF file (required)")
	cmd.MarkFlagRequired("sarif")
	cmd.Flags().String("llm-model", "", "LLM model to use for verification (required)")
	cmd.MarkFlagRequired("llm-model")
	cmd.Flags().Int("llm-max-retries", 3, "Maximum number of retries on transient LLM errors (rate limits, timeouts, 5xx), 0 = no retries")
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings_verify_<timestamp>.sarif.json)")
	cmd.Flags().Bool("upload", false, "Upload the SARIF report to Traceforce Atlas endpoint (requires TRACEFORCE_CLIENT_ID, and TRACEFORCE_CLIENT_SECRET env vars)")
	return cmd
}

func init() {
	rootCmd.AddCommand(NewConfigScanCommand())
	rootCmd.AddCommand(NewRepoScanCommand())
	rootCmd.AddCommand(NewPentestCommand())
	rootCmd.AddCommand(NewVerifyCommand())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeFindings(findings []*proto.Finding, outputPath string, commandName string, upload bool, sourceName string, toolsFilePath string, testFilePath string) (string, error) {
	sarifBytes, err := report.GenerateSarif(findings)
	if err != nil {
		return "", fmt.Errorf("error generating SARIF report: %w", err)
	}
	return writeSarifBytes(sarifBytes, outputPath, commandName, upload, sourceName, toolsFilePath, testFilePath)
}

// writeTargetFindings is writeFindings' target-resolution counterpart: it
// generates target-tagged SARIF (each finding annotated with whether it
// belongs directly to the selected server or to one of its resolved shared
// components) instead of the plain report, then shares the same
// write-to-disk/upload tail as every other command via writeSarifBytes.
func writeTargetFindings(findings []*proto.Finding, target *targetresolve.Target, outputPath string, commandName string, upload bool, sourceName string) (string, error) {
	reasons := make(map[string]string, len(target.IncludedReasons))
	for dir, reason := range target.IncludedReasons {
		reasons[dir] = string(reason)
	}
	sarifBytes, err := report.GenerateSarifForTarget(findings, target.PrimaryRoot(), target.ScanRoots(), reasons)
	if err != nil {
		return "", fmt.Errorf("error generating SARIF report: %w", err)
	}
	return writeSarifBytes(sarifBytes, outputPath, commandName, upload, sourceName, "", "")
}

// writeSarifBytes is the write-to-disk/upload tail shared by writeFindings
// and writeTargetFindings -- the only difference between the two is how the
// SARIF bytes themselves are generated.
func writeSarifBytes(sarifBytes []byte, outputPath string, commandName string, upload bool, sourceName string, toolsFilePath string, testFilePath string) (string, error) {
	if outputPath == "" {
		timestamp := time.Now().Format(time.RFC3339)
		// Make RFC3339 filename-safe by replacing colons with hyphens
		timestamp = strings.ReplaceAll(timestamp, ":", "-")
		outputPath = fmt.Sprintf("findings-%s-%s.sarif.json", commandName, timestamp)
	}

	if err := os.WriteFile(outputPath, sarifBytes, 0644); err != nil {
		return "", fmt.Errorf("error writing to output file %s: %w", outputPath, err)
	}

	fmt.Printf("SARIF report written to %s\n", outputPath)

	// Upload to Traceforce if requested
	if upload {
		if err := uploadToTraceforceAtlas(outputPath, sarifBytes, sourceName, toolsFilePath, testFilePath); err != nil {
			return "", fmt.Errorf("error uploading to Traceforce: %w", err)
		}
		fmt.Printf("SARIF report uploaded to Traceforce Atlas\n")
	}

	return outputPath, nil
}

func cleanupGeneratedFiles(outputPath string, toolsFilePath string, testFilePath string, testPlanDirPath string) error {
	// Delete SARIF output file, if it exists. outputPath is intentionally left
	// empty by the caller when the user specified -o themselves (a user-chosen
	// output path is never auto-deleted), so this must tolerate "" the same
	// way the three removals below already tolerate it for their own paths.
	if outputPath != "" {
		if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error deleting output file %s: %w", outputPath, err)
		}
	}

	// Delete tools file if it exists
	if toolsFilePath != "" {
		if err := os.Remove(toolsFilePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error deleting tools file %s: %w", toolsFilePath, err)
		}
	}

	// Delete test file if it exists
	if testFilePath != "" {
		if err := os.Remove(testFilePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error deleting test file %s: %w", testFilePath, err)
		}
	}

	// Delete test plan directory if it exists
	if testPlanDirPath != "" {
		if err := os.RemoveAll(testPlanDirPath); err != nil {
			return fmt.Errorf("error deleting test plan directory %s: %w", testPlanDirPath, err)
		}
	}

	return nil
}

func validateTraceforceEnv() error {
	clientID := os.Getenv("TRACEFORCE_CLIENT_ID")
	if clientID == "" {
		return fmt.Errorf("TRACEFORCE_CLIENT_ID environment variable is required for upload")
	}

	clientSecret := os.Getenv("TRACEFORCE_CLIENT_SECRET")
	if clientSecret == "" {
		return fmt.Errorf("TRACEFORCE_CLIENT_SECRET environment variable is required for upload")
	}

	return nil
}

func getBearerToken(apiURL string) (string, error) {
	clientID := os.Getenv("TRACEFORCE_CLIENT_ID")
	clientSecret := os.Getenv("TRACEFORCE_CLIENT_SECRET")

	// Prepare request body
	requestBody := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request body: %w", err)
	}

	// Create HTTP request
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/auth/token"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if bypassToken := os.Getenv("TRACEFORCE_VERCEL_BYPASS_TOKEN"); bypassToken != "" {
		req.Header.Set("x-vercel-protection-bypass", bypassToken)
	}

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response to get bearer token
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	if response.AccessToken == "" {
		return "", fmt.Errorf("access_token not found in response")
	}

	// Parse JWT to check expiry
	parts := strings.Split(response.AccessToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}

	// Decode payload (second part) - JWT uses base64url encoding
	payload := parts[1]
	// Add padding if needed for base64 decoding
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try without padding (base64url doesn't require padding)
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("error decoding JWT payload: %w", err)
		}
	}

	// Parse JSON payload
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("error parsing JWT claims: %w", err)
	}

	// Check if token is expired
	if claims.Exp > 0 {
		expiryTime := time.Unix(claims.Exp, 0)
		if time.Now().After(expiryTime) {
			return "", fmt.Errorf("Access token expired at %s. Please generate a new one.", expiryTime.Format(time.RFC3339))
		}
	}

	return response.AccessToken, nil
}

func uploadToTraceforceAtlas(filePath string, sarifBytes []byte, sourceName string, toolsFilePath string, testFilePath string) error {
	// Get API URL from environment variable or use default
	apiURL := os.Getenv("TRACEFORCE_API_ENDPOINT")
	if apiURL == "" {
		apiURL = DefaultTraceforceAPIURL
	}

	// Exchange client credentials for bearer token
	token, err := getBearerToken(apiURL)
	if err != nil {
		return fmt.Errorf("error getting bearer token: %w", err)
	}

	// Create multipart form
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add file field (main SARIF report)
	fileName := filepath.Base(filePath)
	fileWriter, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return fmt.Errorf("error creating form file field: %w", err)
	}
	if _, err := io.Copy(fileWriter, bytes.NewReader(sarifBytes)); err != nil {
		return fmt.Errorf("error writing file to form: %w", err)
	}

	// Add tools_file if provided (upload as regular file, like in the test)
	if toolsFilePath != "" {
		toolsFile, err := os.Open(toolsFilePath)
		if err != nil {
			return fmt.Errorf("error opening tools file %s: %w", toolsFilePath, err)
		}
		defer toolsFile.Close()

		toolsFileName := filepath.Base(toolsFilePath)
		toolsFileWriter, err := writer.CreateFormFile("tools_file", toolsFileName)
		if err != nil {
			return fmt.Errorf("error creating tools_file form field: %w", err)
		}
		if _, err := io.Copy(toolsFileWriter, toolsFile); err != nil {
			return fmt.Errorf("error writing tools_file to form: %w", err)
		}
	}

	// Add test_file if provided (upload as regular file, backend will handle base64 encoding)
	if testFilePath != "" {
		testFile, err := os.Open(testFilePath)
		if err != nil {
			return fmt.Errorf("error opening test file %s: %w", testFilePath, err)
		}
		defer testFile.Close()

		testFileName := filepath.Base(testFilePath)
		testFileWriter, err := writer.CreateFormFile("test_file", testFileName)
		if err != nil {
			return fmt.Errorf("error creating test_file form field: %w", err)
		}
		if _, err := io.Copy(testFileWriter, testFile); err != nil {
			return fmt.Errorf("error writing test_file to form: %w", err)
		}
	}

	// Add source_name field
	if err := writer.WriteField("source_name", sourceName); err != nil {
		return fmt.Errorf("error writing source_name field: %w", err)
	}

	// Close the multipart writer
	if err := writer.Close(); err != nil {
		return fmt.Errorf("error closing multipart writer: %w", err)
	}

	// Create HTTP request
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/scan-reports"
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if bypassToken := os.Getenv("TRACEFORCE_VERCEL_BYPASS_TOKEN"); bypassToken != "" {
		req.Header.Set("x-vercel-protection-bypass", bypassToken)
	}

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// mergeTestPlansFromDir reads all YAML test plan files from a directory and merges them into a single test plan
func mergeTestPlansFromDir(dirPath string) (string, error) {
	// Read all YAML files from the directory
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	// Define types locally to match pentest package structure
	type TestPlan struct {
		Metadata struct {
			Version string `yaml:"version"`
			Target  string `yaml:"target"`
			Focus   string `yaml:"focus"`
		} `yaml:"metadata"`
		Tests []map[string]interface{} `yaml:"tests"`
	}

	var allTests []map[string]interface{}
	var serverNames []string

	// Process each YAML file
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only process .yaml and .yml files, skip merged file
		fileName := file.Name()
		if !strings.HasSuffix(strings.ToLower(fileName), ".yaml") && !strings.HasSuffix(strings.ToLower(fileName), ".yml") {
			continue
		}
		if fileName == "merged_test_plan.yaml" {
			continue
		}

		filePath := filepath.Join(dirPath, fileName)
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Warning: failed to read test plan file %s: %v\n", fileName, err)
			continue
		}

		var testPlan TestPlan
		if err := yaml.Unmarshal(data, &testPlan); err != nil {
			fmt.Printf("Warning: failed to parse YAML in file %s: %v\n", fileName, err)
			continue
		}

		// Collect all tests and server names
		allTests = append(allTests, testPlan.Tests...)
		if testPlan.Metadata.Target != "" {
			serverNames = append(serverNames, testPlan.Metadata.Target)
		}
	}

	if len(allTests) == 0 {
		return "", fmt.Errorf("no test plans found in directory")
	}

	// Create merged plan with single metadata header
	mergedPlan := map[string]interface{}{
		"metadata": map[string]interface{}{
			"version": "1.0",
			"target": func() string {
				if len(serverNames) > 0 {
					return strings.Join(serverNames, ", ")
				}
				return "Multiple MCP Servers"
			}(),
			"focus": "Critical security vulnerabilities",
		},
		"tests": allTests,
	}

	mergedYAML, err := yaml.Marshal(&mergedPlan)
	if err != nil {
		return "", fmt.Errorf("failed to marshal merged YAML: %w", err)
	}

	return string(mergedYAML), nil
}
