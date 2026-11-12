package targetresolve

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A workspace lockfile pins only its workspace's members, as each package
// manager declares them; a lockfile above a project that is no member, such
// as a root package-lock.json for the repository's own tooling, does not.
func TestWorkspaceMembership_Includes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "npm", "package.json"), `{"name": "ws", "workspaces": ["packages/*"]}`)
	writeFile(t, filepath.Join(root, "yarn", "package.json"), `{"name": "ws", "workspaces": {"packages": ["apps/*"]}}`)
	writeFile(t, filepath.Join(root, "tooling", "package.json"), `{"name": "tooling", "private": true}`)
	writeFile(t, filepath.Join(root, "pnpm", "pnpm-workspace.yaml"), "packages:\n  - 'packages/**/*'\n  - '!packages/skip/**'\n")
	writeFile(t, filepath.Join(root, "uv", "pyproject.toml"), "[tool.uv.workspace]\nmembers = [\"servers/*\"]\nexclude = [\"servers/old\"]\n")
	writeFile(t, filepath.Join(root, "cargo", "Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n")
	writeFile(t, filepath.Join(root, "cargo", "crates", "srv", "Cargo.toml"), "[package]\nname = \"srv\"\n")
	writeFile(t, filepath.Join(root, "cargo", "inner", "Cargo.toml"), "[workspace]\nmembers = [\"srv\"]\n")
	writeFile(t, filepath.Join(root, "cargo", "inner", "srv", "Cargo.toml"), "[package]\nname = \"inner-srv\"\n")

	cases := []struct {
		name, lockfileDir, lockfile, projectDir, ecosystem string
		want                                               bool
	}{
		{"npm member", "npm", "package-lock.json", "npm/packages/srv", "node", true},
		{"npm non-member", "npm", "package-lock.json", "npm/tools/srv", "node", false},
		{"yarn's packages object", "yarn", "yarn.lock", "yarn/apps/web", "node", true},
		{"a root without workspaces pins no package below it", "tooling", "package-lock.json", "tooling/srv", "node", false},
		{"pnpm member at depth", "pnpm", "pnpm-lock.yaml", "pnpm/packages/core/srv", "node", true},
		{"pnpm exclusion", "pnpm", "pnpm-lock.yaml", "pnpm/packages/skip/srv", "node", false},
		{"uv member", "uv", "uv.lock", "uv/servers/weather", "python", true},
		{"uv excluded member", "uv", "uv.lock", "uv/servers/old", "python", false},
		{"cargo member", "cargo", "Cargo.lock", "cargo/crates/srv", "rust", true},
		{"cargo crate of a nearer workspace", "cargo", "Cargo.lock", "cargo/inner/srv", "rust", false},
		{"a script's requirements file", "uv", "requirements.txt", "uv/scripts", "python-script", true},
	}
	members := newWorkspaceMembership(root)
	for _, tc := range cases {
		projectDir := filepath.Join(root, filepath.FromSlash(tc.projectDir))
		project := &Project{Dir: projectDir, OwnershipRoot: projectDir, Ecosystem: tc.ecosystem, ManifestPath: filepath.Join(projectDir, "Cargo.toml")}
		if got := members.includes(filepath.Join(root, tc.lockfileDir), tc.lockfile, project); got != tc.want {
			t.Errorf("%s: includes = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMatchWorkspaceGlob(t *testing.T) {
	cases := []struct {
		glob, rel string
		want      bool
	}{
		{"packages/*", "packages/srv", true},
		{"packages/*", "packages/srv/nested", false},
		{"./packages/*", "packages/srv", true},
		{"packages/**/*", "packages/srv", true},
		{"packages/**/*", "packages/a/b/srv", true},
		{"packages/**/*", "packages", false},
		{"examples", "examples", true},
		{"examples/**", "examples", true},
		{"**", "any/depth/at/all", true},
		{"apps/*-mcp", "apps/github-mcp", true},
		{"apps/*-mcp", "apps/github", false},
	}
	for _, tc := range cases {
		if got := matchWorkspaceGlob(tc.glob, tc.rel); got != tc.want {
			t.Errorf("matchWorkspaceGlob(%q, %q) = %v, want %v", tc.glob, tc.rel, got, tc.want)
		}
	}
}

// A repository writes its own globs: one of many **s must not take
// exponential time to reject.
func TestMatchWorkspaceGlob_ManyDoubleStars(t *testing.T) {
	glob := strings.Repeat("**/a/", 40) + "b"
	rel := strings.Repeat("a/", 60) + "c"
	start := time.Now()
	if matchWorkspaceGlob(glob, rel) {
		t.Fatal("matched a path that does not end in b")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v", elapsed)
	}
}
