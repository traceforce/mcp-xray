package targetresolve

import (
	"path/filepath"
	"testing"
)

// Every lockfile the inventory recognizes must also be shown by the
// --list-targets diagnostic and mapped to an ecosystem; the three used to be
// separate lists, which is how uv.lock went missing from the diagnostic one.
func TestLockfileRecognitionIsConsistent(t *testing.T) {
	names := []string{"requirements.txt", "requirements-dev.txt", "dev-requirements.txt"}
	for name := range lockfileEcosystems {
		names = append(names, name)
	}
	for _, name := range names {
		if !matchesLockfile(name) {
			t.Errorf("matchesLockfile(%q) = false", name)
		}
		if !matchesAnyManifestPattern(name) {
			t.Errorf("matchesAnyManifestPattern(%q) = false; --list-targets would hide this lockfile", name)
		}
		if lockfileEcosystem(name) == "" {
			t.Errorf("lockfileEcosystem(%q) is empty", name)
		}
	}
	for _, name := range []string{"README.md", "requirements.in", "notes.txt", "package.json", "Cargo.toml"} {
		if matchesLockfile(name) {
			t.Errorf("matchesLockfile(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"package.json", "Cargo.toml", "pom.xml", "build.gradle.kts", "Pipfile", "Foo.Server.csproj"} {
		if !matchesManifest(name) || !matchesAnyManifestPattern(name) {
			t.Errorf("%q should be recognized as a dependency manifest", name)
		}
	}
}

func TestDependencyFiles_IncludesUvLock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), "[project]\nname = \"x\"\n")
	writeFile(t, filepath.Join(root, "uv.lock"), "version = 1\n")

	found := dependencyFilesOf(root)
	want := []string{filepath.Join(root, "pyproject.toml"), filepath.Join(root, "uv.lock")}
	if len(found) != len(want) || found[0] != want[0] || found[1] != want[1] {
		t.Fatalf("DependencyFiles = %v, want %v", found, want)
	}
}
