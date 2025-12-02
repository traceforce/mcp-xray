package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	reposcan "SecureMCP/internal/repo-scan"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "securemcp",
	Short: "SecureMCP - Security auditing tool for MCP applications",
	Long:  `A comprehensive security auditing tool designed to detect vulnerabilities and misconfigurations in applications using the Model Context Protocol (MCP).`,
}

func NewConfigScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config-scan",
		Short: "Scan the configuration of the MCP server",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scanning the configuration of the MCP server")
		},
	}
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
			jsonBytes, err := json.MarshalIndent(findings, "", "  ")
			if err != nil {
				fmt.Println("Error marshaling findings:", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			if outputPath == "" {
				outputPath = "findings.json"
			}

			err = os.WriteFile(outputPath, jsonBytes, 0644)
			if err != nil {
				fmt.Printf("Error writing to output file %s: %v\n", outputPath, err)
				os.Exit(1)
			}
			fmt.Printf("Findings written to %s\n", outputPath)
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
