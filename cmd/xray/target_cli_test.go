package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mcpxray/internal/targetresolve"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("closing pipe writer failed: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading captured stdout failed: %v", err)
	}
	return buf.String()
}

func TestPrintDiscoveredTargets_PlainTargetPrintsSingleLine(t *testing.T) {
	primary := &targetresolve.Project{Ecosystem: "node", Dir: t.TempDir()}
	target := &targetresolve.Target{
		Name:            "my-server",
		Project:         primary,
		Included:        []*targetresolve.Project{primary},
		IncludedReasons: map[string]targetresolve.InclusionReason{primary.Dir: targetresolve.InclusionPrimary},
	}

	out := captureStdout(t, func() {
		printDiscoveredTargets([]*targetresolve.Target{target}, nil, "")
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 { // header + repo-level note + one target line
		t.Fatalf("expected exactly 3 lines (header, repo-level note, target), got %d: %q", len(lines), out)
	}
	if !strings.Contains(lines[1], "repo-level") {
		t.Errorf("expected the repo-level note line, got %q", lines[1])
	}
	if !strings.Contains(lines[2], "my-server [node]") {
		t.Errorf("expected the target line to contain 'my-server [node]', got %q", lines[2])
	}
}

func TestPrintDiscoveredTargets_EnrichedTargetPrintsExtraLines(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name": "my-server"}`), 0o644); err != nil {
		t.Fatalf("writing package.json fixture failed: %v", err)
	}
	primary := &targetresolve.Project{
		Ecosystem:        "node",
		Dir:              dir,
		Evidence:         []string{"depends on @modelcontextprotocol/sdk", "source contains a server-construction call"},
		WorkspaceSources: []string{"rush"},
		BinNames:         []string{"my-server-cli"},
	}
	shared := &targetresolve.Project{Ecosystem: "node", Dir: filepath.Join(dir, "shared")}
	target := &targetresolve.Target{
		Name:    "my-server",
		Project: primary,
		Included: []*targetresolve.Project{primary, shared},
		IncludedReasons: map[string]targetresolve.InclusionReason{
			primary.Dir: targetresolve.InclusionPrimary,
			shared.Dir:  targetresolve.InclusionSharedDependency,
		},
	}
	other := &targetresolve.Project{Name: "unrelated-tool", Dir: t.TempDir(), Role: targetresolve.RoleUnrelated}

	out := captureStdout(t, func() {
		printDiscoveredTargets([]*targetresolve.Target{target}, []*targetresolve.Project{primary, shared, other}, dir)
	})

	if !strings.Contains(out, "repo-level") {
		t.Errorf("expected the repo-level note, got %q", out)
	}
	if !strings.Contains(out, "evidence: depends on @modelcontextprotocol/sdk; source contains a server-construction call") {
		t.Errorf("expected an evidence line, got %q", out)
	}
	if !strings.Contains(out, "workspace: rush") {
		t.Errorf("expected a workspace line, got %q", out)
	}
	if !strings.Contains(out, "bin: my-server-cli") {
		t.Errorf("expected a bin line, got %q", out)
	}
	if !strings.Contains(out, "scope: 1 shared-dependency") {
		t.Errorf("expected an inclusion-reason breakdown line, got %q", out)
	}
	if !strings.Contains(out, "dependency files (1):") || !strings.Contains(out, "package.json") {
		t.Errorf("expected a dependency files section naming package.json, got %q", out)
	}
	if !strings.Contains(out, "package.json") || strings.Contains(out, dir+string(filepath.Separator)+"package.json") {
		t.Errorf("expected the dependency file path to be relative to repoRoot, not absolute, got %q", out)
	}
	if !strings.Contains(out, "not included in this scope (1 other project(s)):") || !strings.Contains(out, "unrelated (1): unrelated-tool") {
		t.Errorf("expected the unrelated sibling project to be listed, grouped by role, as not included, got %q", out)
	}
}
