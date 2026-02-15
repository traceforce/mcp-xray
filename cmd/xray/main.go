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

	configscan "mcpxray/internal/configscan"
	"mcpxray/internal/pentest"
	"mcpxray/internal/report"
	reposcan "mcpxray/internal/reposcan"
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
				scanner, err := configscan.NewConfigScanner(configPath, analyzerType, llmModel, toolsOutputFile)
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

			// Build config - by default scan everything (no excludes)
			config := &reposcan.Config{
				MaxFileSize:   10 * 1024 * 1024, // 10MB default
				ExcludedPaths: []string{},       // Empty by default - scan everything
			}

			// Apply max file size if specified
			if maxFileSize > 0 {
				config.MaxFileSize = maxFileSize
			}

			// Apply excluded paths
			defaultConfig := reposcan.DefaultConfig()
			if useDefaultExcludes {
				// Use default excluded paths
				config.ExcludedPaths = defaultConfig.ExcludedPaths
			}
			if len(excludedPaths) > 0 {
				// User-provided excludes override or extend
				config.ExcludedPaths = append(defaultConfig.ExcludedPaths, excludedPaths...)
			}

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

			var allFindings []*proto.Finding
			ctx := context.Background()

			// Run CVE/SCA scan if enabled
			if runCVE {
				scaScanner := reposcan.NewSCAScanner(repoPath, config)
				cveFindings, err := scaScanner.Scan(ctx)
				if err != nil {
					fmt.Println("Error running CVE scan:", err)
					os.Exit(1)
				}
				allFindings = append(allFindings, cveFindings...)
			}

			// Run secrets scan if enabled
			if runSecrets {
				secretsScanner := reposcan.NewSecretsScanner(repoPath, config)
				secretsFindings, err := secretsScanner.Scan(ctx)
				if err != nil {
					fmt.Println("Error running secrets scan:", err)
					os.Exit(1)
				}
				allFindings = append(allFindings, secretsFindings...)
			}

			// Run SAST scan if enabled
			if runSAST {
				sastScanner := reposcan.NewSASTScanner(repoPath, config)
				sastFindings, err := sastScanner.Scan(ctx)
				if err != nil {
					fmt.Println("Error running SAST scan:", err)
					os.Exit(1)
				}
				allFindings = append(allFindings, sastFindings...)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			cleanup, _ := cmd.Flags().GetBool("clean-up")
			// For repo-scan, use repo path basename or default to "repo-scan"
			sourceName := "repo-scan"
			if repoPath != "." {
				sourceName = filepath.Base(repoPath)
			}
			actualOutputPath, err := writeFindings(allFindings, outputPath, "repo-scan", upload, sourceName, "", "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			// Cleanup generated files if requested and upload was successful
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
	cmd.Flags().Int64("max-file-size", 0, "Maximum file size in bytes to scan (0 uses default: 10MB)")
	cmd.Flags().StringArrayP("exclude-paths", "e", []string{}, "Path pattern to exclude from scanning (can be specified multiple times)")
	cmd.Flags().Bool("use-default-excludes", true, "Use default exclude paths (e.g., node_modules, .git, etc.). By default, certain files and directories are excluded from scanning.")
	cmd.Flags().Bool("cve", false, "Run CVE/SCA scan (software composition analysis)")
	cmd.Flags().Bool("secrets", false, "Run secrets scan")
	cmd.Flags().Bool("sast", false, "Run SAST scan (static application security testing)")
	cmd.Flags().Bool("upload", false, "Upload the SARIF report to Traceforce Atlas endpoint (requires TRACEFORCE_CLIENT_ID, and TRACEFORCE_CLIENT_SECRET env vars)")
	cmd.Flags().Bool("clean-up", false, "Remove all generated files after successful upload (requires --upload)")
	return cmd
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
			pentestTool, err := pentest.NewPentestTool(configPath, llmModel)
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

			// If using directory mode and uploading, merge all test plans
			if isDirectory && upload {
				mergedTestPlan, err := mergeTestPlansFromDir(testPlanPath)
				if err != nil {
					fmt.Printf("Warning: failed to merge test plans: %v\n", err)
				} else if mergedTestPlan != "" {
					// Write merged test plan to a temporary file
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

			verifyTool, err := pentest.NewVerifyTool("", llmModel)
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

	if outputPath == "" {
		timestamp := time.Now().Format(time.RFC3339)
		// Make RFC3339 filename-safe by replacing colons with hyphens
		timestamp = strings.ReplaceAll(timestamp, ":", "-")
		outputPath = fmt.Sprintf("findings-%s-%s.sarif.json", commandName, timestamp)
	}

	err = os.WriteFile(outputPath, sarifBytes, 0644)
	if err != nil {
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
	// Delete SARIF output file
	if err := os.Remove(outputPath); err != nil {
		return fmt.Errorf("error deleting output file %s: %w", outputPath, err)
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
	url := strings.TrimSuffix(apiURL, "/") + "/api/v1/api-keys"
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
