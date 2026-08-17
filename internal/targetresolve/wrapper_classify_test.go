package targetresolve

import "testing"

func TestPromoteWrapperServers_PromotesWrapperReachingAConfirmedServer(t *testing.T) {
	server := &Project{Name: "real-server", Dir: "/repo/real-server", Ecosystem: "node", Role: RoleMCPServer}
	wrapper := &Project{Name: "wrapper", Dir: "/repo/wrapper", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"wrapper-cli"}}
	wrapper.LocalDeps = []string{server.Dir}

	promoteWrapperServers([]*Project{server, wrapper})

	if wrapper.Role != RoleMCPServer {
		t.Errorf("expected wrapper to be promoted to RoleMCPServer, got %v", wrapper.Role)
	}
}

func TestPromoteWrapperServers_NoPromotionWithoutOwnEntrypointEvidence(t *testing.T) {
	server := &Project{Name: "real-server", Dir: "/repo/real-server", Ecosystem: "node", Role: RoleMCPServer}
	dep := &Project{Name: "plain-dep", Dir: "/repo/plain-dep", Ecosystem: "node", Role: RoleUnrelated}
	dep.LocalDeps = []string{server.Dir}

	promoteWrapperServers([]*Project{server, dep})

	if dep.Role != RoleUnrelated {
		t.Errorf("expected a project with no bin/startup evidence of its own to stay RoleUnrelated, got %v", dep.Role)
	}
}

func TestPromoteWrapperServers_MultiHopFixedPoint(t *testing.T) {
	// wrapper A -> wrapper B -> real server C. A is only promotable once B
	// is (B must be promoted first in the fixed-point loop, or on a later
	// iteration).
	c := &Project{Name: "server-c", Dir: "/repo/c", Ecosystem: "node", Role: RoleMCPServer}
	b := &Project{Name: "wrapper-b", Dir: "/repo/b", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"b-cli"}}
	a := &Project{Name: "wrapper-a", Dir: "/repo/a", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"a-cli"}}
	b.LocalDeps = []string{c.Dir}
	a.LocalDeps = []string{b.Dir}

	promoteWrapperServers([]*Project{a, b, c})

	if b.Role != RoleMCPServer {
		t.Errorf("expected wrapper-b to be promoted, got %v", b.Role)
	}
	if a.Role != RoleMCPServer {
		t.Errorf("expected wrapper-a to be promoted via the multi-hop closure, got %v", a.Role)
	}
}

func TestPromoteWrapperServers_TestShapedProjectNeverPromoted(t *testing.T) {
	server := &Project{Name: "real-server", Dir: "/repo/real-server", Ecosystem: "node", Role: RoleMCPServer}
	testProj := &Project{Name: "server.Tests", Dir: "/repo/server.Tests", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"test-runner"}}
	testProj.LocalDeps = []string{server.Dir}

	promoteWrapperServers([]*Project{server, testProj})

	if testProj.Role == RoleMCPServer {
		t.Errorf("expected a test-shaped project to never be promoted to RoleMCPServer, got %v", testProj.Role)
	}
}
