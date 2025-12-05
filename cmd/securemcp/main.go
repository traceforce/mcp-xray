package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	configscan "SecureMCP/internal/config-scan"
	reposcan "SecureMCP/internal/repo-scan"
	"SecureMCP/proto"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "securemcp",
	Short: "SecureMCP - Security auditing tool for MCP applications",
	Long:  `A comprehensive security auditing tool designed to detect vulnerabilities and misconfigurations in applications using the Model Context Protocol (MCP).`,
}

func NewConfigScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config-scan",
		Short: "Scan the configuration of the MCP server",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scanning the configuration of the MCP server")
			configPath := "."
			if len(args) > 0 {
				configPath = args[0]
			}

			// Parse scanner config from CLI flags
			uid, _ := cmd.Flags().GetString("uid")
			username, _ := cmd.Flags().GetString("username")

			scannerConfig := &configscan.ScannerConfig{}
			if uid != "" && username != "" {
				userAccount := &configscan.UserAccount{
					Uid:      uid,
					Username: username,
				}
				scannerConfig = configscan.NewScannerConfig(userAccount)
			}

			scanner := configscan.NewConfigScanner(configPath, scannerConfig)
			findings, err := scanner.Scan(context.Background())
			if err != nil {
				fmt.Println("Error scanning configuration:", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			if err := writeFindings(findings, outputPath); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().String("uid", "", "User ID for scanner configuration")
	cmd.Flags().String("username", "", "Username for scanner configuration")
	cmd.Flags().StringP("output", "o", "", "Output file path for scan results (default: findings.json)")
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
			scanner := reposcan.NewDefaultRepoScanner(repoPath)
			findings, err := scanner.Scan(context.Background())
			if err != nil {
				fmt.Println("Error scanning repository:", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			if err := writeFindings(findings, outputPath); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringP("output", "o", "", "Output file path for scan results (default: findings.json)")
	return cmd
}

func init() {
	rootCmd.AddCommand(NewConfigScanCommand())
	rootCmd.AddCommand(NewRepoScanCommand())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeFindings(findings []proto.Finding, outputPath string) error {
	jsonBytes, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling findings: %w", err)
	}

	if outputPath == "" {
		outputPath = "findings.json"
	}

	err = os.WriteFile(outputPath, jsonBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing to output file %s: %w", outputPath, err)
	}

	fmt.Printf("Findings written to %s\n", outputPath)
	return nil
}
