package taint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// findOpengrep resolves the engine only from an explicit, pinned source:
// MCPXRAY_OPENGREP_BIN, then bin/opengrep next to the mcpxray binary (installed by
// `make install-opengrep`). It deliberately does NOT fall back to an `opengrep` on PATH,
// so plain repo-scan never auto-activates taint from an unrelated/unpinned engine; point
// MCPXRAY_OPENGREP_BIN at one on PATH to use it. "" when none is usable.
func findOpengrep() string {
	if b := os.Getenv("MCPXRAY_OPENGREP_BIN"); b != "" && isExec(b) {
		return b
	}
	if exe, err := os.Executable(); err == nil {
		if local := filepath.Join(filepath.Dir(exe), "bin", "opengrep"); isExec(local) {
			return local
		}
	}
	return ""
}

func isExec(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	// Windows has no Unix exec bit, so the mode check would wrongly reject a real
	// opengrep.exe pointed at by MCPXRAY_OPENGREP_BIN; a resolvable file is runnable.
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode()&0o111 != 0
}

// runOpenGrep executes one taint scan and decodes the JSON output. Any failure
// (missing binary, timeout, non-JSON) returns an error; the caller treats an error
// as "no findings" so a broken engine never crashes repo-scan.
func runOpenGrep(ctx context.Context, cfg Config, rulePath, target string) (*ogOutput, error) {
	bin := cfg.OpengrepBin
	if bin == "" {
		return nil, fmt.Errorf("opengrep binary not found")
	}
	// Default any unset limit (mirrors DefaultConfig) so a partial Config never fires the
	// deadline instantly or passes 0 to the CLI.
	timeout, perRule, maxBytes := cfg.TimeoutSec, cfg.PerRuleTimeoutSec, cfg.MaxTargetBytes
	if timeout <= 0 {
		timeout = 300
	}
	if perRule <= 0 {
		perRule = 30
	}
	if maxBytes <= 0 {
		maxBytes = 2_000_000
	}
	// Derive from the caller's ctx so repo-scan cancellation aborts the engine too.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// --experimental enables --taint-intrafile (inter-method taint within one file).
	args := []string{
		"scan", "--config", rulePath, "--json", "--quiet",
		"--experimental", "--taint-intrafile",
		"--timeout", strconv.Itoa(perRule),
		"--max-target-bytes", strconv.Itoa(maxBytes),
	}
	for _, e := range cfg.Excludes {
		args = append(args, "--exclude="+e)
	}
	args = append(args, target)
	cmd := exec.CommandContext(ctx, bin, args...)
	// Run with the scan root as CWD so any CWD-relative path the engine emits resolves
	// under the repo, not an unrelated directory. Only when target is an absolute dir
	// (what Engine.Scan passes); a relative target is left to resolve against the CWD.
	if filepath.IsAbs(target) {
		cmd.Dir = target
	}
	// On timeout the context kills the wrapper, but a still-running opengrep-cli child
	// inherits stdout and keeps Output() blocked on the open pipe. WaitDelay bounds that
	// wait and then force-closes the pipes, so the deadline actually stops the scan.
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("opengrep timed out after %ds", timeout)
	}
	if ctx.Err() != nil {
		// Caller cancelled mid-scan: the output is incomplete, so surface an error rather
		// than parsing partial stdout as a clean result.
		return nil, fmt.Errorf("opengrep cancelled: %w", ctx.Err())
	}
	// OpenGrep's exit code is the reliable signal: 0 = clean, 1 = findings, >=2 = a real
	// engine/ruleset failure (a skipped unparseable target file does not raise it). Key
	// fatality off the code -- not the JSON error level, which is "warn" for some load
	// failures -- so a broken run is never silently reported as 0 findings.
	fatalExit := false
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() >= 2 {
		fatalExit = true
	}
	if len(out) == 0 {
		if err != nil {
			// Surface the engine's stderr (rule/parse errors) instead of a bare "exit status 2".
			if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
				return nil, fmt.Errorf("opengrep produced no output: %s", ee.Stderr)
			}
			return nil, fmt.Errorf("opengrep produced no output: %w", err)
		}
		return &ogOutput{}, nil
	}
	var res ogOutput
	if e := json.Unmarshal(out, &res); e != nil {
		return nil, fmt.Errorf("opengrep output not valid JSON: %w", e)
	}
	if fatalExit {
		return nil, fmt.Errorf("opengrep: %s", firstErrorMessage(res.Errors))
	}
	return &res, nil
}

// firstErrorMessage returns a message from the engine's errors[] to surface a failed
// run, preferring a level "error" entry; "" errors fall back to a generic message.
func firstErrorMessage(errs []ogError) string {
	for _, e := range errs {
		if e.Level == "error" && e.Message != "" {
			return e.Message
		}
	}
	for _, e := range errs {
		if e.Message != "" {
			return e.Message
		}
	}
	return "engine exited with an error"
}
