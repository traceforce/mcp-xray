package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mcpxray/internal/aggregation"
	reposcan "mcpxray/internal/reposcan"
	"mcpxray/internal/targetresolve"
	"mcpxray/proto"
)

// cliArgsEnv carries runCLI's arguments, JSON-encoded, to the child process.
const cliArgsEnv = "MCPXRAY_TEST_CLI_ARGS"

// TestMain runs mcpxray itself instead of the tests when runCLI re-executes
// the test binary.
func TestMain(m *testing.M) {
	if encoded := os.Getenv(cliArgsEnv); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			panic(err)
		}
		os.Args = append([]string{"mcpxray"}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runCLI runs mcpxray with args, plus env in its environment, and returns
// what it printed and its exit code.
func runCLI(t *testing.T, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(append(os.Environ(), cliArgsEnv+"="+string(encoded)), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var exitErr *exec.ExitError
	if err := cmd.Run(); errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String(), exitCode
}

func TestReadTargetFlags(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantEnabled   bool
		wantExplicit  bool
		wantErrSubstr string
	}{
		{name: "no target flags keeps the full-repository scan", args: nil},
		{name: "--target alone enables target resolution", args: []string{"--target", "my-server"}, wantEnabled: true, wantExplicit: true},
		{name: "--target-id alone enables target resolution", args: []string{"--target-id", "t-1"}, wantEnabled: true, wantExplicit: true},
		{name: "--all-targets alone enables target resolution", args: []string{"--all-targets"}, wantEnabled: true, wantExplicit: true},
		{name: "--list-targets enables target resolution without selecting", args: []string{"--list-targets"}, wantEnabled: true},
		{name: "--list-targets --json is accepted", args: []string{"--list-targets", "--json"}, wantEnabled: true},
		{name: "--explain-scope enables target resolution without selecting", args: []string{"--explain-scope"}, wantEnabled: true},
		{name: "--include-repo-global enables target resolution without selecting", args: []string{"--include-repo-global"}, wantEnabled: true},
		{name: "--target-resolution enables target resolution without selecting", args: []string{"--target-resolution"}, wantEnabled: true},
		{name: "--output-dir alone keeps the full-repository scan", args: []string{"--output-dir", "out"}},
		{name: "--json needs --list-targets", args: []string{"--json"}, wantErrSubstr: "--json requires --list-targets"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRepoScanCommand()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) failed: %v", tc.args, err)
			}
			got, err := readTargetFlags(cmd)
			if tc.wantErrSubstr != "" {
				if err == nil || err.Error() != tc.wantErrSubstr {
					t.Fatalf("readTargetFlags(%v) error = %v, want %q", tc.args, err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readTargetFlags(%v) failed: %v", tc.args, err)
			}
			if got.enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", got.enabled, tc.wantEnabled)
			}
			if got.explicitSelection() != tc.wantExplicit {
				t.Errorf("explicitSelection() = %v, want %v", got.explicitSelection(), tc.wantExplicit)
			}
		})
	}
}

// TestAttribute credits a finding to the targets its file's ownership names,
// and leaves a file no target owns unowned, which ownedByATarget then drops
// from the workspace-root dependency check.
func TestAttribute(t *testing.T) {
	repoRoot := t.TempDir()
	plan := &targetresolve.ScanPlan{
		RepoRoot: repoRoot,
		FileOwnership: map[string]*targetresolve.FileOwnership{
			"package-lock.json": {
				TargetIDs:    []string{"t-a", "t-b"},
				ComponentIDs: []string{"c-a", "c-b"},
				Relation:     targetresolve.RelationWorkspaceRoot,
				Context:      "production",
			},
		},
	}
	owned := &proto.Finding{Tool: "osv", RuleId: "CVE-1", File: filepath.Join(repoRoot, "package-lock.json")}
	unregistered := &proto.Finding{Tool: "osv", RuleId: "CVE-2", File: filepath.Join(repoRoot, "unrelated-file.json")}

	af := attribute(plan, owned, "workspace-root-fallback", "exec-1")
	if af.Finding != owned || af.ScanUnitID != "workspace-root-fallback" || af.ExecutionID != "exec-1" {
		t.Errorf("attribute did not carry the finding, scan unit and execution through: %+v", af)
	}
	if af.Relation != string(targetresolve.RelationWorkspaceRoot) {
		t.Errorf("Relation = %q, want %q", af.Relation, targetresolve.RelationWorkspaceRoot)
	}
	if len(af.TargetIDs) != 2 || af.TargetIDs[0] != "t-a" || af.TargetIDs[1] != "t-b" {
		t.Errorf("TargetIDs = %v, want both t-a and t-b", af.TargetIDs)
	}

	unowned := attribute(plan, unregistered, "workspace-root-fallback", "")
	if len(unowned.TargetIDs) != 0 {
		t.Errorf("a file with no ownership record was credited to %v", unowned.TargetIDs)
	}
	if !ownedByATarget(af) || ownedByATarget(unowned) {
		t.Error("ownedByATarget must keep the fallback lockfile's finding and drop the unowned one")
	}
}

// writeTwoServerRepo writes a repository holding two Python MCP servers,
// servers/alpha and servers/beta, and returns its root.
func writeTwoServerRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	for _, name := range []string{"alpha", "beta"} {
		files := map[string]string{
			"pyproject.toml":                 "[project]\nname = \"" + name + "\"\nversion = \"0.1.0\"\ndependencies = [\"mcp>=1.0\"]\n[project.scripts]\n" + name + " = \"" + name + ".server:main\"\n",
			filepath.Join(name, "server.py"): "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP(\"" + name + "\")\ndef main():\n    mcp.run()\n",
		}
		for rel, content := range files {
			path := filepath.Join(repo, "servers", name, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return repo
}

// Resolving targets reads the whole repository, so a plain repo-scan whose
// output is not a terminal (CI, a pipe) skips the --list-targets hint.
func TestPrintTargetHint_SkippedWhenStdoutIsNotATerminal(t *testing.T) {
	repo := writeTwoServerRepo(t)
	resolution, err := targetresolve.Resolve(repo)
	if err != nil || len(resolution.Targets) != 2 {
		t.Fatalf("fixture resolves to %v, %v; want two targets", resolution, err)
	}
	if out := captureStdout(t, func() { printTargetHint(repo) }); out != "" {
		t.Errorf("printTargetHint printed %q to a pipe, want nothing", out)
	}
}

// writeFile writes content to the repository-relative path rel under repo.
func writeFile(t *testing.T, repo, rel, content string) {
	t.Helper()
	path := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runTargetScanForTest runs a target scan of repoPath with the default
// excludes, discarding its stdout.
func runTargetScanForTest(t *testing.T, repoPath string, targets targetFlags, selection reposcan.ScannerSelection, output reportOutput) (handled bool, err error) {
	t.Helper()
	targets.enabled = true
	base := *reposcan.DefaultConfig()
	base.Root = repoPath
	captureStdout(t, func() {
		handled, err = runTargetScan(context.Background(), repoPath, targets, base, selection, output)
	})
	return handled, err
}

// sarifRun is the part of a SARIF report's single run the tests read.
type sarifRun struct {
	Results []struct {
		Message    struct{ Text string }  `json:"message"`
		Properties map[string]interface{} `json:"properties"`
	} `json:"results"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func readSARIFRun(t *testing.T, path string) sarifRun {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct{ Runs []sarifRun }
	if err := json.Unmarshal(data, &report); err != nil || len(report.Runs) != 1 {
		t.Fatalf("report %s: %v, %d runs", path, err, len(report.Runs))
	}
	return report.Runs[0]
}

func TestRunTargetScan_RejectsARootThatIsNotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "repo.txt")
	writeFile(t, filepath.Dir(file), "repo.txt", "not a repository\n")
	for _, root := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		if _, err := runTargetScanForTest(t, root, targetFlags{list: true}, reposcan.ScannerSelection{}, reportOutput{}); err == nil || !strings.Contains(err.Error(), "scan root "+root) {
			t.Errorf("--list-targets on %s: err = %v, want a scan root error", root, err)
		}
	}
}

// Resolution and the scanners see a symlinked root under its real path, so
// targets are discovered and findings attributed to them.
func TestRunTargetScan_ScansThroughASymlinkedRoot(t *testing.T) {
	repo := writeTwoServerRepo(t)
	token := "gh" + "p_" + "8sR2kQ9vLx4TzW7nB1mYc5pD3fH6jE0aK2uV" // split so this file holds no token
	writeFile(t, repo, "servers/alpha/alpha/config.py", "GITHUB_TOKEN = \""+token+"\"\n")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(repo, link); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}
	output := filepath.Join(t.TempDir(), "report.sarif.json")

	handled, err := runTargetScanForTest(t, link+string(filepath.Separator), targetFlags{all: true}, reposcan.ScannerSelection{Secrets: true}, reportOutput{path: output})
	if !handled || err != nil {
		t.Fatalf("runTargetScan = %v, %v; want a handled scan", handled, err)
	}
	results := readSARIFRun(t, output).Results
	if len(results) == 0 {
		t.Fatal("no findings reported through the symlinked root")
	}
	for _, result := range results {
		if ids, _ := result.Properties["targetIds"].([]interface{}); len(ids) != 1 {
			t.Errorf("finding %q credited to targets %v, want alpha's", result.Message.Text, result.Properties["targetIds"])
		}
	}
}

// A server under a directory the user excluded is not scanned for secrets
// or SAST findings, as a full scan never walks into it: the exclusion holds
// although the scanners only match patterns below the unit's own root.
func TestRunTargetScan_ExcludedAncestorStaysExcluded(t *testing.T) {
	repo := writeTwoServerRepo(t)
	token := "gh" + "p_" + "8sR2kQ9vLx4TzW7nB1mYc5pD3fH6jE0aK2uV" // split so this file holds no token
	writeFile(t, repo, "servers/alpha/alpha/config.py", "GITHUB_TOKEN = \""+token+"\"\n")
	output := filepath.Join(t.TempDir(), "report.sarif.json")
	base := *reposcan.DefaultConfig()
	base.Root = repo
	base.ExcludedPaths = append(base.ExcludedPaths, "servers")

	var handled bool
	var err error
	captureStdout(t, func() {
		handled, err = runTargetScan(context.Background(), repo, targetFlags{enabled: true, all: true, includeRepoGlobal: true}, base, reposcan.ScannerSelection{Secrets: true}, reportOutput{path: output})
	})
	if !handled || err != nil {
		t.Fatalf("runTargetScan = %v, %v; want a handled scan", handled, err)
	}
	if results := readSARIFRun(t, output).Results; len(results) != 0 {
		t.Errorf("reported %d findings from the excluded servers/ directory, want none", len(results))
	}
}

func TestTargetSourceName(t *testing.T) {
	alpha := &targetresolve.Target{ID: "target-a", Name: "alpha", Project: &targetresolve.Project{RelDir: "servers/alpha"}}
	beta := &targetresolve.Target{ID: "target-b", Name: "beta", Project: &targetresolve.Project{RelDir: "servers/beta"}}
	server1 := &targetresolve.Target{ID: "target-c", Name: "server", Project: &targetresolve.Project{RelDir: "a"}}
	server2 := &targetresolve.Target{ID: "target-d", Name: "server", Project: &targetresolve.Project{RelDir: "b"}}
	all := []*targetresolve.Target{alpha, beta, server1, server2}
	cases := []struct {
		repoPath string
		selected []*targetresolve.Target
		want     string
	}{
		{"/src/mono", []*targetresolve.Target{alpha}, "mono/alpha"},
		{"/src/mono", []*targetresolve.Target{alpha, beta}, "mono"},
		{".", []*targetresolve.Target{alpha}, "repo-scan/alpha"},
		// Two servers named "server" keep separate histories.
		{"/src/mono", []*targetresolve.Target{server1}, "mono/a"},
		{"/src/mono", []*targetresolve.Target{server2}, "mono/b"},
	}
	for _, tc := range cases {
		plan := &targetresolve.ScanPlan{SelectedTargets: tc.selected}
		if got := targetSourceName(tc.repoPath, plan, all); got != tc.want {
			t.Errorf("targetSourceName(%q, %d targets) = %q, want %q", tc.repoPath, len(tc.selected), got, tc.want)
		}
	}
}

// The SARIF report counts the plan's files instead of listing them: a large
// repository's inventory would otherwise make up most of the report.
func TestRunTargetScan_SARIFCountsThePlansFiles(t *testing.T) {
	repo := writeTwoServerRepo(t)
	output := filepath.Join(t.TempDir(), "report.sarif.json")
	if _, err := runTargetScanForTest(t, repo, targetFlags{all: true}, reposcan.ScannerSelection{Secrets: true}, reportOutput{path: output}); err != nil {
		t.Fatal(err)
	}

	var plan struct {
		Inventory      json.RawMessage `json:"inventory"`
		InventoryCount int             `json:"inventoryCount"`
		Units          []struct {
			Root      string          `json:"root"`
			Files     json.RawMessage `json:"files"`
			FileCount int             `json:"fileCount"`
		} `json:"scanUnits"`
	}
	if err := json.Unmarshal(readSARIFRun(t, output).Properties["scanPlan"], &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Inventory != nil || plan.InventoryCount != 4 {
		t.Errorf("scanPlan inventory = %s, inventoryCount = %d; want no list and a count of 4", plan.Inventory, plan.InventoryCount)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scanPlan has %d units, want 2", len(plan.Units))
	}
	for _, unit := range plan.Units {
		if unit.Files != nil || unit.FileCount != 2 {
			t.Errorf("unit %s files = %s, fileCount = %d; want no list and a count of 2", unit.Root, unit.Files, unit.FileCount)
		}
	}
}

// fakeOpengrep stands in for the opengrep taint engine with a shell script
// running script.
func fakeOpengrep(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in taint engine is a shell script")
	}
	engine := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(engine, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPXRAY_OPENGREP_BIN", engine)
}

// A taint engine that fails leaves a unit's SAST execution partial, not
// failed: the target scan completes, as a full-repository scan does, and
// the execution records say what was missed.
func TestRunTargetScan_PartialSASTExecutionDoesNotFailTheScan(t *testing.T) {
	fakeOpengrep(t, "echo boom >&2\nexit 2\n")
	repo := writeTwoServerRepo(t)
	output := filepath.Join(t.TempDir(), "report.sarif.json")
	if _, err := runTargetScanForTest(t, repo, targetFlags{all: true}, reposcan.ScannerSelection{SAST: true}, reportOutput{path: output}); err != nil {
		t.Fatalf("runTargetScan = %v, want the scan to complete", err)
	}

	var executions []reposcan.ScannerExecution
	if err := json.Unmarshal(readSARIFRun(t, output).Properties["executions"], &executions); err != nil {
		t.Fatal(err)
	}
	partial := 0
	for _, execution := range executions {
		if execution.Scanner == "sast" {
			if execution.Status != reposcan.ScannerPartial || !strings.Contains(execution.Error, "opengrep") {
				t.Errorf("sast execution of %s = %s (%q), want partial with the opengrep error", execution.ScanUnitID, execution.Status, execution.Error)
			}
			partial++
		}
	}
	if partial != 2 {
		t.Errorf("%d sast executions, want one per server", partial)
	}
}

// A taint finding names its sink relative to the repository, as a
// full-repository scan does, not relative to the unit that found it.
func TestRunTargetScan_TaintFindingNamesTheRepositoryRelativeFile(t *testing.T) {
	repo := writeTwoServerRepo(t)
	server, err := filepath.EvalSymlinks(filepath.Join(repo, "servers", "alpha", "alpha", "server.py")) // the engine is handed the resolved root
	if err != nil {
		t.Fatal(err)
	}
	// An engine reporting one command injection at alpha's server.py:3; the
	// scan of beta's unit drops it as outside its root.
	result := `{"results":[{"check_id":"mcpxray-py-command_injection","path":"` + server + `","start":{"line":3},"end":{"line":3},` +
		`"extra":{"metavars":{"$F":{"abstract_content":"main"},"$SRC":{"abstract_content":"cmd","start":{"line":3}}}}}],"errors":[]}`
	fakeOpengrep(t, "cat <<'EOF'\n"+result+"\nEOF\nexit 1\n")
	output := filepath.Join(t.TempDir(), "report.sarif.json")
	if _, err := runTargetScanForTest(t, repo, targetFlags{all: true}, reposcan.ScannerSelection{SAST: true}, reportOutput{path: output}); err != nil {
		t.Fatal(err)
	}

	var messages []string
	for _, result := range readSARIFRun(t, output).Results {
		if strings.HasPrefix(result.Message.Text, "Tainted MCP tool input") {
			messages = append(messages, result.Message.Text)
		}
	}
	if len(messages) != 1 || !strings.Contains(messages[0], " at servers/alpha/alpha/server.py:3.") {
		t.Errorf("taint findings = %q, want one naming the sink at servers/alpha/alpha/server.py:3", messages)
	}
}

// --list-targets uploads nothing, so --upload does not need Atlas
// credentials with it.
func TestRepoScan_ListTargetsWithUploadNeedsNoCredentials(t *testing.T) {
	repo := writeTwoServerRepo(t)
	stdout, stderr, code := runCLI(t, []string{"TRACEFORCE_CLIENT_ID=", "TRACEFORCE_CLIENT_SECRET="}, "repo-scan", repo, "--list-targets", "--upload")
	if code != 0 || !strings.Contains(stdout, "Discovered MCP targets:") {
		t.Errorf("exit %d, stdout %q, stderr %q; want the target list and exit 0", code, stdout, stderr)
	}
}

// With --json, stdout holds the listing alone: an error goes to stderr.
func TestRepoScan_ListTargetsJSONReportsErrorsOnStderr(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	stdout, stderr, code := runCLI(t, nil, "repo-scan", missing, "--list-targets", "--json")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "cannot read scan root") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 1 with the error on stderr only", code, stdout, stderr)
	}
}

// rawFindingCount is what the scanners reported, before the findings no
// selected target owns are left out and duplicates merged.
func TestScanDiagnostics(t *testing.T) {
	finding := func() *proto.Finding {
		return &proto.Finding{Tool: "gitleaks", RuleId: "token", File: "/repo/a.py", Line: 1}
	}
	result := &planScanResult{
		executions: []reposcan.ScannerExecution{{Scanner: "gitleaks", FindingCount: 2}, {Scanner: "gitleaks", FindingCount: 2}},
		attributed: []aggregation.AttributedFinding{{Finding: finding(), ScanUnitID: "u1", ExecutionID: "e1"}, {Finding: finding(), ScanUnitID: "u2", ExecutionID: "e2"}, {Finding: &proto.Finding{Tool: "gitleaks", RuleId: "token", File: "/repo/b.py", Line: 1}, ScanUnitID: "u2", ExecutionID: "e2"}},
	}
	aggregated := aggregation.Aggregate("/repo", result.attributed)

	diagnostics := scanDiagnostics(result, aggregated)
	want := map[string]int{"rawFindingCount": 4, "outOfScopeFindingCount": 1, "uniqueFindingCount": 2, "duplicateFindingCount": 1}
	for key, value := range want {
		if diagnostics[key] != value {
			t.Errorf("%s = %v, want %d", key, diagnostics[key], value)
		}
	}
}
