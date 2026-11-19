package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigScanFailedConfigIsNotClean(t *testing.T) {
	if os.Getenv("MCPXRAY_CONFIG_SCAN_CHILD") == "1" {
		rootCmd.SetArgs([]string{
			"config-scan",
			os.Getenv("MCPXRAY_CONFIG"),
			"-o", os.Getenv("MCPXRAY_OUT"),
			"--tools-output", os.Getenv("MCPXRAY_TOOLS"),
		})
		if err := rootCmd.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// An unreachable host is covered by TestScanUnresolvableHostKeepsFindingsAndSecrets.
	// That test dials the network, and make ci skips internal/configscan for that reason.

	t.Run("invalid json", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "mcp.json")
		if err := os.WriteFile(configPath, []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}

		code, sarif, output := runConfigScan(t, dir, configPath)
		if code == 0 {
			t.Fatalf("invalid JSON exited 0 and the scan saved a clean report:\n%s\noutput:\n%s", sarif, output)
		}
	})

	t.Run("stdio config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "mcp.json")
		body := `{
  "mcpServers": {
    "local": {
      "command": "/usr/bin/true"
    }
  }
}
`
		if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}

		code, sarif, output := runConfigScan(t, dir, configPath)
		if code != 0 {
			t.Fatalf("stdio config exited %d\nSARIF:\n%s\noutput:\n%s", code, sarif, output)
		}
		if !strings.Contains(sarif, "stdio-transport-detected") {
			t.Fatalf("the scan omitted the stdio server:\n%s\noutput:\n%s", sarif, output)
		}
	})
}

func runConfigScan(t *testing.T, dir, configPath string) (int, string, string) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigScanFailedConfigIsNotClean$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"MCPXRAY_CONFIG_SCAN_CHILD=1",
		"MCPXRAY_CONFIG="+configPath,
		"MCPXRAY_OUT="+filepath.Join(dir, "findings.sarif.json"),
		"MCPXRAY_TOOLS="+filepath.Join(dir, "tools.json"),
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run config-scan: %v\n%s", err, out)
		}
		code = exitErr.ExitCode()
	}

	sarif, readErr := os.ReadFile(filepath.Join(dir, "findings.sarif.json"))
	if readErr != nil {
		t.Fatalf("read SARIF: %v\n%s", readErr, out)
	}
	return code, string(sarif), string(out)
}
