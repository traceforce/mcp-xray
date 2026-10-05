package targetresolve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGitmodulesPaths(t *testing.T) {
	data := []byte(`[submodule "vendor/foo"]
	path = vendor/foo
	url = https://example.com/foo.git
[submodule "libs/bar"]
	path = libs/bar
	url = https://example.com/bar.git
`)
	paths := parseGitmodulesPaths(data)
	if len(paths) != 2 || paths[0] != "vendor/foo" || paths[1] != "libs/bar" {
		t.Errorf("expected [vendor/foo libs/bar], got %v", paths)
	}
}

func TestDetectSubmoduleWarnings_MissingDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".gitmodules"), `[submodule "vendor/foo"]
	path = vendor/foo
	url = https://example.com/foo.git
`)
	warnings := detectSubmoduleWarnings(root)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for missing submodule dir, got %d: %v", len(warnings), warnings)
	}
}

func TestDetectSubmoduleWarnings_EmptyDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".gitmodules"), `[submodule "vendor/foo"]
	path = vendor/foo
	url = https://example.com/foo.git
`)
	if err := os.MkdirAll(filepath.Join(root, "vendor", "foo"), 0755); err != nil {
		t.Fatalf("failed to create empty submodule dir: %v", err)
	}

	warnings := detectSubmoduleWarnings(root)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for empty submodule dir, got %d: %v", len(warnings), warnings)
	}
}

func TestDetectSubmoduleWarnings_InitializedSubmoduleIsSilent(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".gitmodules"), `[submodule "vendor/foo"]
	path = vendor/foo
	url = https://example.com/foo.git
`)
	writeFile(t, filepath.Join(root, "vendor", "foo", "README.md"), "hello")

	warnings := detectSubmoduleWarnings(root)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for a populated submodule dir, got %v", warnings)
	}
}

func TestDetectSubmoduleWarnings_NoGitmodulesFile(t *testing.T) {
	root := t.TempDir()
	if warnings := detectSubmoduleWarnings(root); warnings != nil {
		t.Errorf("expected nil warnings when .gitmodules does not exist, got %v", warnings)
	}
}
