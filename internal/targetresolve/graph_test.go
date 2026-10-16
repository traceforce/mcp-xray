package targetresolve

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTransitiveClosure(t *testing.T) {
	a := &Project{Name: "a", Dir: "/repo/a"}
	b := &Project{Name: "b", Dir: "/repo/b"}
	c := &Project{Name: "c", Dir: "/repo/c"}
	a.LocalDeps = []string{b.Dir}
	b.LocalDeps = []string{c.Dir}

	dirs := indexProjectDirs([]*Project{a, b, c})

	closure := transitiveClosure(a, dirs)
	if len(closure) != 3 {
		t.Fatalf("expected closure of 3 (a, b, c), got %d: %+v", len(closure), closure)
	}
}

// A LocalDeps entry naming a directory several projects share is the
// project of the depending project's own ecosystem, whichever of them was
// discovered first, and none when no project there is of its ecosystem.
func TestProjectDirsDep_FollowsTheDependentsEcosystem(t *testing.T) {
	node := &Project{Name: "liba", Dir: "/repo/liba", Ecosystem: "node"}
	python := &Project{Name: "liba-py-tools", Dir: "/repo/liba", Ecosystem: "python"}
	name := func(p *Project) string {
		if p == nil {
			return "none"
		}
		return p.Name
	}
	for _, discovered := range [][]*Project{{node, python}, {python, node}} {
		dirs := indexProjectDirs(discovered)
		for ecosystem, want := range map[string]*Project{"node": node, "python": python, "go": nil} {
			if got := dirs.dep(&Project{Dir: "/repo/srv", Ecosystem: ecosystem}, "/repo/liba"); got != want {
				t.Errorf("discovered %s first: a %s dependency on liba/ = %s, want %s", discovered[0].Ecosystem, ecosystem, name(got), name(want))
			}
		}
	}
}

func TestTransitiveClosure_CycleSafe(t *testing.T) {
	a := &Project{Name: "a", Dir: "/repo/a"}
	b := &Project{Name: "b", Dir: "/repo/b"}
	a.LocalDeps = []string{b.Dir}
	b.LocalDeps = []string{a.Dir} // cycle back to a

	dirs := indexProjectDirs([]*Project{a, b})

	closure := transitiveClosure(a, dirs)
	if len(closure) != 2 {
		t.Fatalf("expected cycle-safe closure of 2, got %d: %+v", len(closure), closure)
	}
}

// A server's own development dependencies are part of the code it is built
// and tested with; a dependency's are never installed with it. Reproduces
// python-sdk, whose examples depend on the SDK and the SDK's dev group on
// an examples package.
func TestTransitiveClosure_FollowsOnlyTheServersOwnDevelopmentDependencies(t *testing.T) {
	server := &Project{Name: "server", Dir: "/repo/server"}
	testkit := &Project{Name: "testkit", Dir: "/repo/testkit"}
	sdk := &Project{Name: "sdk", Dir: "/repo"}
	stories := &Project{Name: "stories", Dir: "/repo/stories"}
	server.LocalDeps, server.DevLocalDeps = []string{sdk.Dir, testkit.Dir}, []string{testkit.Dir}
	sdk.LocalDeps, sdk.DevLocalDeps = []string{stories.Dir}, []string{stories.Dir}

	closure := transitiveClosure(server, indexProjectDirs([]*Project{server, testkit, sdk, stories}))

	var names []string
	for _, p := range closure {
		names = append(names, p.Name)
	}
	if got, want := strings.Join(names, ","), "server,sdk,testkit"; got != want {
		t.Errorf("closure = %s, want %s", got, want)
	}
}

func TestBuildTargets_PromotesSharedLibrary(t *testing.T) {
	server := &Project{Name: "server", Dir: "/repo/server", Role: RoleMCPServer}
	shared := &Project{Name: "shared", Dir: "/repo/shared", Role: RoleUnrelated}
	server.LocalDeps = []string{shared.Dir}

	targets := buildTargets([]*Project{server, shared})
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if shared.Role != RoleSharedLibrary {
		t.Errorf("expected shared to be promoted to RoleSharedLibrary, got %v", shared.Role)
	}
	if len(targets[0].Included) != 2 {
		t.Errorf("expected target.Included to have 2 entries (server + shared), got %d", len(targets[0].Included))
	}
}

func TestBuildTargets_TwoIndependentServersDoNotShareScope(t *testing.T) {
	// Pattern 1: independent server collections. Selecting one server's
	// target must not pull in an unrelated sibling server or its
	// dependencies.
	serverA := &Project{Name: "server-a", Dir: "/repo/server-a", Role: RoleMCPServer}
	serverB := &Project{Name: "server-b", Dir: "/repo/server-b", Role: RoleMCPServer}
	shared := &Project{Name: "shared", Dir: "/repo/shared", Role: RoleUnrelated}
	serverA.LocalDeps = []string{shared.Dir}
	// serverB has no local deps -- it is fully independent.

	targets := buildTargets([]*Project{serverA, serverB, shared})
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	var targetA, targetB *Target
	for _, tgt := range targets {
		switch tgt.Name {
		case "server-a":
			targetA = tgt
		case "server-b":
			targetB = tgt
		}
	}
	if targetA == nil || targetB == nil {
		t.Fatalf("expected targets named server-a and server-b, got %+v", targets)
	}
	if len(targetA.Included) != 2 {
		t.Errorf("expected server-a's target to include itself + shared, got %d", len(targetA.Included))
	}
	if len(targetB.Included) != 1 {
		t.Errorf("expected server-b's target to include only itself, got %d", len(targetB.Included))
	}
	for _, p := range targetB.Included {
		if p == shared {
			t.Errorf("server-b's target must not include the shared component it never referenced")
		}
	}
}

func TestBuildTargets_ClientRoleNotOverwritten(t *testing.T) {
	server := &Project{Name: "server", Dir: "/repo/server", Role: RoleMCPServer}
	client := &Project{Name: "client", Dir: "/repo/client", Role: RoleMCPClient}
	server.LocalDeps = []string{client.Dir}

	buildTargets([]*Project{server, client})

	if client.Role != RoleMCPClient {
		t.Errorf("expected client's more specific role to be preserved, got %v", client.Role)
	}
}

func TestBuildTargets_DemotesFallbackClassifiedSharedInfrastructure(t *testing.T) {
	// Reproduces the real microsoft/mcp repo exactly: three independent
	// servers, each confirmed by their own server.json (RoleConfirmedByManifest),
	// each transitively depending (via a per-server "core" shim, omitted here
	// for brevity -- a direct edge is equivalent for this test) on one shared
	// library that itself independently satisfies the per-ecosystem
	// fallback signal (it has an SDK dependency and contains the one real
	// SDK construction call), making it look exactly like a fourth server by
	// source signal alone.
	serverA := &Project{Name: "server-a", Dir: "/repo/server-a", Role: RoleMCPServer, RoleConfirmedByManifest: true}
	serverB := &Project{Name: "server-b", Dir: "/repo/server-b", Role: RoleMCPServer, RoleConfirmedByManifest: true}
	serverC := &Project{Name: "server-c", Dir: "/repo/server-c", Role: RoleMCPServer, RoleConfirmedByManifest: true}
	// sharedCore is NOT confirmed by its own manifest -- it was classified
	// RoleMCPServer only by the per-ecosystem fallback heuristic.
	sharedCore := &Project{Name: "shared-core", Dir: "/repo/shared-core", Role: RoleMCPServer, RoleConfirmedByManifest: false}

	serverA.LocalDeps = []string{sharedCore.Dir}
	serverB.LocalDeps = []string{sharedCore.Dir}
	serverC.LocalDeps = []string{sharedCore.Dir}

	targets := buildTargets([]*Project{serverA, serverB, serverC, sharedCore})

	if sharedCore.Role != RoleSharedLibrary {
		t.Errorf("expected sharedCore to be demoted to RoleSharedLibrary, got %v", sharedCore.Role)
	}
	if len(targets) != 3 {
		t.Fatalf("expected exactly 3 targets (the confirmed servers only, not sharedCore as a 4th), got %d: %+v", len(targets), targetNames(targets))
	}
	for _, tgt := range targets {
		if tgt.Name == "shared-core" {
			t.Error("shared-core must not appear as its own target")
		}
	}
	// It must still be pulled into every server's scan scope.
	for _, tgt := range targets {
		found := false
		for _, p := range tgt.Included {
			if p == sharedCore {
				found = true
			}
		}
		if !found {
			t.Errorf("expected target %s to still include the demoted shared-core in its scan scope", tgt.Name)
		}
	}
}

func TestBuildTargets_ManifestConfirmedServerIsNeverDemoted(t *testing.T) {
	// The Tier-1-immunity guarantee: a project with its own server.json is a
	// real server no matter what else depends on it.
	serverA := &Project{Name: "server-a", Dir: "/repo/server-a", Role: RoleMCPServer, RoleConfirmedByManifest: true}
	realServerAlsoUsedAsALibrary := &Project{Name: "real-server-2", Dir: "/repo/real-server-2", Role: RoleMCPServer, RoleConfirmedByManifest: true}
	serverA.LocalDeps = []string{realServerAlsoUsedAsALibrary.Dir}

	targets := buildTargets([]*Project{serverA, realServerAlsoUsedAsALibrary})

	if realServerAlsoUsedAsALibrary.Role != RoleMCPServer {
		t.Errorf("expected manifest-confirmed server to remain RoleMCPServer even though another server depends on it, got %v", realServerAlsoUsedAsALibrary.Role)
	}
	if len(targets) != 2 {
		t.Fatalf("expected both manifest-confirmed servers to get their own target, got %d", len(targets))
	}
}

func TestDemoteReachableFallbackServers_ImmuneWithOwnBinEntry(t *testing.T) {
	// Reproduces the twilio-labs/mcp shape at the graph level: a project
	// reachable from a confirmed server, not manifest-confirmed itself, but
	// with its own bin entry (independent proof of being launchable on its
	// own) must not be demoted -- it's a second, genuinely independent
	// server, not shared infrastructure.
	serverA := &Project{Name: "wrapper", Dir: "/repo/wrapper", Role: RoleMCPServer}
	serverB := &Project{Name: "base-server", Dir: "/repo/base-server", Role: RoleMCPServer, BinNames: []string{"base-server-cli"}}
	serverA.LocalDeps = []string{serverB.Dir}

	targets := buildTargets([]*Project{serverA, serverB})

	if serverB.Role != RoleMCPServer {
		t.Errorf("expected base-server (own bin entry) to remain RoleMCPServer, got %v", serverB.Role)
	}
	if len(targets) != 2 {
		t.Fatalf("expected both to get their own target, got %d: %+v", len(targets), targetNames(targets))
	}
}

func TestIncludeTestDependents_PullsInReverseDependentTestProject(t *testing.T) {
	primary := &Project{Name: "server", Dir: "/repo/src/server"}
	testProj := &Project{Name: "server-tests", Dir: "/repo/tests/server.tests", RelDir: "tests/server.tests"}
	testProj.LocalDeps = []string{primary.Dir}

	dirs := indexProjectDirs([]*Project{primary, testProj})

	added := includeTestDependents(primary, map[*Project]bool{primary: true}, []*Project{primary, testProj}, dirs)
	if len(added) != 1 || added[0] != testProj {
		t.Fatalf("expected testProj to be pulled in via its reverse dependency on primary, got %+v", added)
	}
}

func TestIncludeTestDependents_NonTestShapedDependentIsNeverPulledIn(t *testing.T) {
	// The reverse-closure mechanism is deliberately scoped to test-shaped
	// projects only (isTestShapedProject) -- a blanket reverse-closure would
	// pull in any unrelated consumer of primary, which is exactly the
	// "pulling in an entire unrelated workspace" failure mode this package
	// otherwise avoids.
	primary := &Project{Name: "server", Dir: "/repo/src/server"}
	otherApp := &Project{Name: "other-app", Dir: "/repo/apps/other-app"}
	otherApp.LocalDeps = []string{primary.Dir}

	dirs := indexProjectDirs([]*Project{primary, otherApp})

	added := includeTestDependents(primary, map[*Project]bool{primary: true}, []*Project{primary, otherApp}, dirs)
	if len(added) != 0 {
		t.Fatalf("expected a non-test-shaped dependent to never be pulled in, got %+v", added)
	}
}

func TestIncludeTestDependents_UnrelatedServersOwnTestsDoNotLeakViaSharedDep(t *testing.T) {
	// server-a and server-b both depend on the same shared library; server-b
	// also has its own test project. server-b's tests must never leak into
	// server-a's target scope merely because both servers touch the same
	// shared component -- only a test project that reaches the TARGET's own
	// primary project qualifies.
	shared := &Project{Name: "shared", Dir: "/repo/shared"}
	serverA := &Project{Name: "server-a", Dir: "/repo/server-a"}
	serverB := &Project{Name: "server-b", Dir: "/repo/server-b"}
	serverA.LocalDeps = []string{shared.Dir}
	serverB.LocalDeps = []string{shared.Dir}
	serverBTests := &Project{Name: "server-b-tests", Dir: "/repo/tests/server-b", RelDir: "tests/server-b"}
	serverBTests.LocalDeps = []string{serverB.Dir}

	dirs := indexProjectDirs([]*Project{shared, serverA, serverB, serverBTests})
	allProjects := []*Project{shared, serverA, serverB, serverBTests}

	addedForA := includeTestDependents(serverA, map[*Project]bool{serverA: true, shared: true}, allProjects, dirs)
	if len(addedForA) != 0 {
		t.Fatalf("expected server-b's own tests to never leak into server-a's target scope, got %+v", addedForA)
	}
}

func TestBuildTargets_IncludesTestDependentAndTagsReason(t *testing.T) {
	server := &Project{Name: "server", Dir: "/repo/src/server", Role: RoleMCPServer}
	shared := &Project{Name: "shared", Dir: "/repo/shared", Role: RoleUnrelated}
	server.LocalDeps = []string{shared.Dir}
	tests := &Project{Name: "server-tests", Dir: "/repo/tests/server.tests", RelDir: "tests/server.tests", Role: RoleMCPClient}
	tests.LocalDeps = []string{server.Dir}

	targets := buildTargets([]*Project{server, shared, tests})
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	target := targets[0]
	if len(target.Included) != 3 {
		t.Fatalf("expected server + shared + tests included, got %d: %+v", len(target.Included), target.Included)
	}
	if target.IncludedReasons[filepath.Clean(server.Dir)] != InclusionPrimary {
		t.Errorf("expected primary reason, got %v", target.IncludedReasons[filepath.Clean(server.Dir)])
	}
	if target.IncludedReasons[filepath.Clean(shared.Dir)] != InclusionSharedDependency {
		t.Errorf("expected shared-dependency reason, got %v", target.IncludedReasons[filepath.Clean(shared.Dir)])
	}
	if target.IncludedReasons[filepath.Clean(tests.Dir)] != InclusionTestDependent {
		t.Errorf("expected test-dependent reason, got %v", target.IncludedReasons[filepath.Clean(tests.Dir)])
	}
	if tests.Role != RoleMCPClient {
		t.Errorf("expected the test-dependent project's existing Role to be left untouched (never relabeled shared-library, which means the opposite direction), got %v", tests.Role)
	}
}

func TestBuildTargets_SingleServerNoTestDependentsHasOnlyPrimaryReason(t *testing.T) {
	// Regression requirement 1: a normal single-server repository (no
	// test-shaped siblings, no shared deps) is unaffected by this phase.
	server := &Project{Name: "server", Dir: "/repo/server", Role: RoleMCPServer}
	targets := buildTargets([]*Project{server})
	if len(targets[0].Included) != 1 || targets[0].IncludedReasons[filepath.Clean(server.Dir)] != InclusionPrimary {
		t.Errorf("expected single-server repo to have exactly {primary: InclusionPrimary}, got Included=%+v IncludedReasons=%+v", targets[0].Included, targets[0].IncludedReasons)
	}
}

func TestBuildTargets_TestDependentClosureDoesNotDuplicateAlreadyIncludedSharedDep(t *testing.T) {
	// Regression requirement 7: a shared component reachable via both the
	// forward edge and the test-dependent's own closure must appear exactly
	// once in Included, not twice.
	server := &Project{Name: "server", Dir: "/repo/server", Role: RoleMCPServer}
	shared := &Project{Name: "shared", Dir: "/repo/shared", Role: RoleUnrelated}
	server.LocalDeps = []string{shared.Dir}
	tests := &Project{Name: "server-tests", Dir: "/repo/tests/server.tests", RelDir: "tests/server.tests", Role: RoleMCPClient}
	tests.LocalDeps = []string{server.Dir, shared.Dir}

	targets := buildTargets([]*Project{server, shared, tests})
	included := targets[0].Included
	count := 0
	for _, p := range included {
		if p == shared {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected shared to appear exactly once in Included despite being reachable via both the forward edge and the test-dependent's own closure, got %d", count)
	}
	if len(included) != 3 {
		t.Errorf("expected exactly 3 included projects (server, shared, tests), got %d: %+v", len(included), included)
	}
}

func targetNames(targets []*Target) []string {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Name
	}
	return names
}

// A library whose source merely contains a startup call (a connect helper)
// is still shared code when a server depends on it: only a declared
// entrypoint makes it a standalone server.
func TestDemoteReachableFallbackServers_StartupCallAloneDoesNotProtect(t *testing.T) {
	root := t.TempDir()
	coreDir := filepath.Join(root, "core")
	writeFile(t, filepath.Join(coreDir, "index.ts"), "export async function start(server, transport) { await server.connect(transport) }\n")
	server := &Project{Name: "server", Dir: filepath.Join(root, "server"), Ecosystem: "node", Role: RoleMCPServer, BinNames: []string{"server"}}
	core := &Project{Name: "core", Dir: coreDir, Ecosystem: "node", Role: RoleMCPServer}
	server.LocalDeps = []string{core.Dir}

	targets := buildTargets([]*Project{server, core})

	if core.Role != RoleSharedLibrary {
		t.Errorf("core role = %v, want shared-library", core.Role)
	}
	if len(targets) != 1 {
		t.Errorf("targets = %v, want only the server", targetNames(targets))
	}
}

// A server that a package.json script starts, or (outside Node) whose own
// source starts it, is a program of its own and keeps its target when
// another server depends on it.
func TestDemoteReachableFallbackServers_LaunchableServersStay(t *testing.T) {
	root := t.TempDir()
	scripted := &Project{Name: "oauth", Dir: filepath.Join(root, "oauth"), ManifestPath: filepath.Join(root, "oauth", "package.json"), Ecosystem: "node", Role: RoleMCPServer}
	writeFile(t, scripted.ManifestPath, `{"name": "oauth", "scripts": {"server": "tsx server.ts", "build": "tsc"}}`)
	writeFile(t, filepath.Join(scripted.Dir, "server.ts"), "import { McpServer } from \"@modelcontextprotocol/sdk/server/mcp.js\";\nconst server = new McpServer({ name: \"oauth\", version: \"1\" });\napp.listen(3000)\n")
	python := &Project{Name: "weather", Dir: filepath.Join(root, "weather"), Ecosystem: "python", Role: RoleMCPServer}
	writeFile(t, filepath.Join(python.Dir, "server.py"), "if __name__ == '__main__':\n    mcp.run()\n")
	gateway := &Project{Name: "gateway", Dir: filepath.Join(root, "gateway"), Ecosystem: "node", Role: RoleMCPServer, BinNames: []string{"gateway"}}
	gateway.LocalDeps = []string{scripted.Dir, python.Dir}

	targets := buildTargets([]*Project{gateway, scripted, python})

	if scripted.Role != RoleMCPServer || python.Role != RoleMCPServer || len(targets) != 3 {
		t.Errorf("roles = %v, %v; targets = %v; want all three servers kept", scripted.Role, python.Role, targetNames(targets))
	}
}

// Demotion follows the dependencies a server runs with, and never runs both
// ways: a server whose tests pull in another server (a Python dependency
// group) is not that server's library, and two servers depending on each
// other -- a core whose tests use the app built on it -- are neither the
// other's library.
func TestDemoteReachableFallbackServers_DevelopmentEdgesAndCycles(t *testing.T) {
	t.Run("development dependency", func(t *testing.T) {
		harness := &Project{Name: "harness", Dir: "/repo/harness", Ecosystem: "python", Role: RoleMCPServer}
		weather := &Project{Name: "weather", Dir: "/repo/weather", Ecosystem: "python", Role: RoleMCPServer}
		harness.LocalDeps = []string{weather.Dir}
		harness.DevLocalDeps = []string{weather.Dir}

		targets := buildTargets([]*Project{harness, weather})

		if weather.Role != RoleMCPServer || len(targets) != 2 {
			t.Errorf("weather role = %v, targets = %v; want both servers kept", weather.Role, targetNames(targets))
		}
	})
	t.Run("cycle", func(t *testing.T) {
		app := &Project{Name: "app", Dir: "/repo/packages/app", Ecosystem: "node", Role: RoleMCPServer}
		core := &Project{Name: "core", Dir: "/repo/packages/core", Ecosystem: "node", Role: RoleMCPServer}
		app.LocalDeps = []string{core.Dir}
		core.LocalDeps = []string{app.Dir}

		targets := buildTargets([]*Project{app, core})

		if app.Role != RoleMCPServer || core.Role != RoleMCPServer || len(targets) != 2 {
			t.Errorf("roles = %v, %v; targets = %v; want both servers kept", app.Role, core.Role, targetNames(targets))
		}
	})
}
