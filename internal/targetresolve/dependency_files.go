package targetresolve

import (
	"path/filepath"
	"strings"
)

// lockfileEcosystems maps every lockfile basename this package recognizes to
// the Project.Ecosystem family whose dependency versions it pins. It is the
// single source of truth for matchesLockfile (inventory), lockfileEcosystem
// (a unit's own-lockfile check) and matchesAnyManifestPattern (--list-targets
// diagnostics), so they can never drift apart. The names mirror osv-scanner's
// lockfile extractors (go.sum is kept as Go's conventional lockfile even though
// osv-scanner resolves modern Go modules from go.mod itself); requirements
// files are matched separately by isRequirementsFile because their names vary.
var lockfileEcosystems = map[string]string{
	"go.sum":                      "go",
	"package-lock.json":           "node",
	"npm-shrinkwrap.json":         "node",
	"yarn.lock":                   "node",
	"pnpm-lock.yaml":              "node",
	"bun.lock":                    "node",
	"poetry.lock":                 "python",
	"Pipfile.lock":                "python",
	"uv.lock":                     "python",
	"pdm.lock":                    "python",
	"gradle.lockfile":             "java",
	"buildscript-gradle.lockfile": "java",
	"Cargo.lock":                  "rust",
	"packages.lock.json":          "dotnet",
}

// workspaceLockfiles are the lockfiles a package manager writes ONCE for a
// whole workspace, at its root: npm/yarn/pnpm/bun workspaces, Cargo
// workspaces and uv workspaces. A member with no lockfile of its own is
// genuinely pinned by the root one -- the only case
// workspaceRootFallbackLockfiles exists for. Every other lockfile describes
// the single project in its own directory (a root poetry.lock pins the root
// project, not a nested one), and Go, Java and .NET never share a root
// lockfile with nested projects at all, so none of those may stand in for a
// nested project's missing lockfile.
var workspaceLockfiles = map[string]bool{
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
	"bun.lock":            true,
	"Cargo.lock":          true,
	"uv.lock":             true,
}

// dependencyManifestPatterns lists the dependency-declaring manifests (as
// opposed to lockfiles) shown by --list-targets and flagged in the inventory.
// Patterns use filepath.Match syntax.
var dependencyManifestPatterns = []string{
	"go.mod",
	"package.json",
	"pyproject.toml", "Pipfile", "setup.py",
	"pom.xml", "build.gradle", "build.gradle.kts",
	"Cargo.toml",
	"*.csproj",
}

// isRequirementsFile mirrors osv-scanner's own requirements.txt extractor
// rule (a .txt file whose name contains "requirements"), so requirements.txt,
// requirements-dev.txt and dev-requirements.txt are all recognized.
func isRequirementsFile(name string) bool {
	return filepath.Ext(name) == ".txt" && strings.Contains(name, "requirements")
}

// lockfileEcosystem returns the Project.Ecosystem family a lockfile basename
// belongs to, or "" when name is not a recognized lockfile.
func lockfileEcosystem(name string) string {
	if ecosystem, ok := lockfileEcosystems[name]; ok {
		return ecosystem
	}
	if isRequirementsFile(name) {
		return "python"
	}
	return ""
}

func matchesLockfile(name string) bool {
	return lockfileEcosystem(name) != ""
}

func matchesManifest(name string) bool {
	for _, pattern := range dependencyManifestPatterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// matchesAnyManifestPattern reports whether name is any dependency file --
// manifest or lockfile -- that --list-targets should show.
func matchesAnyManifestPattern(name string) bool {
	return matchesManifest(name) || matchesLockfile(name)
}

// rootLockfileCanPin reports whether the lockfile named lockfile, in a
// directory above a project of the given Project.Ecosystem that has none of
// its own, can stand in for it. Only a workspace lockfile of the project's
// own family qualifies -- with one exception: a manifest-less Python script
// has no package manager of its own, so a plain requirements.txt above it
// (not a dev/docs variant) is how its dependencies are installed.
func rootLockfileCanPin(lockfile, ecosystem string) bool {
	if ecosystem == "python-script" && lockfile == "requirements.txt" {
		return true
	}
	return workspaceLockfiles[lockfile] && lockfileEcosystem(lockfile) == ecosystemFamily(ecosystem)
}

// ecosystemFamily maps a Project.Ecosystem value onto the family used by
// lockfileEcosystems. A manifest-less Python script resolves its dependencies
// exactly like any other Python project; a project synthesized purely from a
// server.json ("unknown") has no dependency ecosystem at all.
func ecosystemFamily(ecosystem string) string {
	switch ecosystem {
	case "python-script":
		return "python"
	case "unknown":
		return ""
	}
	return ecosystem
}
