package targetresolve

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolve_IndependentServerCollection builds a minimal pattern-1 fixture
// on disk (two independent Go MCP servers, one shared Go library referenced
// by only one of them) and checks Resolve() end-to-end: two targets with
// correct, non-overlapping Included sets.
func TestResolve_IndependentServerCollection(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "server-a", "go.mod"), `module example.com/server-a

go 1.22

require (
	github.com/modelcontextprotocol/go-sdk v1.3.1
	example.com/shared v0.0.0
)
`)
	writeFile(t, filepath.Join(root, "server-a", "main.go"), `package main
import "github.com/modelcontextprotocol/go-sdk/mcp"
func main() { _ = mcp.NewServer(nil, nil) }
`)

	writeFile(t, filepath.Join(root, "server-b", "go.mod"), `module example.com/server-b

go 1.22

require github.com/modelcontextprotocol/go-sdk v1.3.1
`)
	writeFile(t, filepath.Join(root, "server-b", "main.go"), `package main
import "github.com/modelcontextprotocol/go-sdk/mcp"
func main() { _ = mcp.NewServer(nil, nil) }
`)

	writeFile(t, filepath.Join(root, "shared", "go.mod"), "module example.com/shared\n\ngo 1.22\n")
	writeFile(t, filepath.Join(root, "shared", "util.go"), "package shared\nfunc Helper() {}\n")

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if len(resolution.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}

	var targetA, targetB *Target
	for _, tgt := range resolution.Targets {
		switch tgt.Name {
		case "server-a":
			targetA = tgt
		case "server-b":
			targetB = tgt
		}
	}
	if targetA == nil || targetB == nil {
		t.Fatalf("expected targets named server-a and server-b, got %+v", resolution.Targets)
	}

	rootsA := targetA.ScanRoots()
	if len(rootsA) != 2 {
		t.Errorf("expected server-a's scan roots to include itself + shared, got %v", rootsA)
	}
	rootsB := targetB.ScanRoots()
	if len(rootsB) != 1 {
		t.Errorf("expected server-b's scan roots to include only itself, got %v", rootsB)
	}
}

// TestResolve_ClientOnlyRepoHasZeroTargets is the built-in negative-case
// validation described in the plan: a project that depends on an MCP SDK and
// uses it only as a client (mirroring mcp-xray's own repository) must
// resolve to zero server targets rather than being mistaken for one.
func TestResolve_ClientOnlyRepoHasZeroTargets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module example.com/scanner

go 1.22

require github.com/modelcontextprotocol/go-sdk v1.3.1
`)
	writeFile(t, filepath.Join(root, "main.go"), `package main
import "github.com/modelcontextprotocol/go-sdk/mcp"
func main() { _ = mcp.NewClient(nil, nil) }
`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 0 {
		t.Errorf("expected 0 targets for a client-only repo, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
}

// TestResolve_MixedRoleWorkspace covers pattern 3: a workspace containing a
// server, a client, and a shared library, plus a consumer-config-only
// project that must not be mistaken for a server.
func TestResolve_MixedRoleWorkspace(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "packages", "server", "package.json"), `{
		"name": "server",
		"dependencies": { "@modelcontextprotocol/sdk": "^1.0.0", "shared": "workspace:*" }
	}`)
	writeFile(t, filepath.Join(root, "packages", "server", "index.ts"), `
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
new McpServer({ name: "x", version: "1.0" });
`)

	writeFile(t, filepath.Join(root, "packages", "client", "package.json"), `{
		"name": "client",
		"dependencies": { "@modelcontextprotocol/sdk": "^1.0.0" }
	}`)
	writeFile(t, filepath.Join(root, "packages", "client", "index.ts"), `
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
new Client({ name: "x", version: "1.0" });
`)

	writeFile(t, filepath.Join(root, "packages", "shared", "package.json"), `{"name": "shared"}`)

	writeFile(t, filepath.Join(root, "packages", "docs-site", "package.json"), `{"name": "docs-site"}`)
	writeFile(t, filepath.Join(root, "packages", "docs-site", "mcp.json"), `{"mcpServers": {"github": {"command": "npx"}}}`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if len(resolution.Targets) != 1 {
		t.Fatalf("expected exactly 1 target (only 'server' qualifies), got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
	if resolution.Targets[0].Name != "server" {
		t.Errorf("expected the single target to be 'server', got %q", resolution.Targets[0].Name)
	}
	if len(resolution.Targets[0].ScanRoots()) != 2 {
		t.Errorf("expected server's scan roots to include itself + shared, got %v", resolution.Targets[0].ScanRoots())
	}

	var client, docsSite *Project
	for _, p := range resolution.Projects {
		switch p.Name {
		case "client":
			client = p
		case "docs-site":
			docsSite = p
		}
	}
	if client == nil || client.Role != RoleMCPClient {
		t.Errorf("expected 'client' to be classified RoleMCPClient, got %+v", client)
	}
	if docsSite == nil || docsSite.Role != RoleConsumerConfigOnly {
		t.Errorf("expected 'docs-site' to be classified RoleConsumerConfigOnly, got %+v", docsSite)
	}
}

// TestResolve_WrapperServerWithIndependentSiblingServer reproduces the
// twilio-labs/mcp shape end-to-end: a package with its own bin entry and a
// `.connect(transport)` call, but whose own source imports nothing from the
// SDK's server namespace at all -- it only instantiates a workspace-local
// class and a workspace-local transport helper (the real SDK Server
// construction lives entirely in a sibling it depends on via a
// plain-version dependency, no workspace:/file:/link: protocol). This
// isolates promoteWrapperServers as the mechanism under test (the real
// repo's own main.ts happens to also import StdioServerTransport directly,
// which the Item 1 namespace signal alone would already catch -- this
// fixture deliberately removes that so the dependency-closure mechanism is
// what's actually being exercised). Both must resolve as independent
// targets -- the wrapper via promoteWrapperServers, the sibling immune to
// demotion via its own bin entry.
func TestResolve_WrapperServerWithIndependentSiblingServer(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "twilio-mcp-workspace",
		"workspaces": ["packages/mcp", "packages/openapi-mcp-server"]
	}`)

	writeFile(t, filepath.Join(root, "packages", "mcp", "package.json"), `{
		"name": "@twilio-alpha/mcp",
		"bin": { "twilio-mcp-server": "./build/index.js" },
		"dependencies": {
			"@twilio-alpha/openapi-mcp-server": "0.7.0"
		}
	}`)
	writeFile(t, filepath.Join(root, "packages", "mcp", "src", "main.ts"), `
import TwilioOpenAPIMCPServer from "@app/server";
import { createStdioTransport } from "@app/transport";

const server = new TwilioOpenAPIMCPServer({});
const transport = createStdioTransport();
await server.connect(transport);
`)

	writeFile(t, filepath.Join(root, "packages", "openapi-mcp-server", "package.json"), `{
		"name": "@twilio-alpha/openapi-mcp-server",
		"bin": { "openapi-mcp-server": "build/simple.js" },
		"dependencies": { "@modelcontextprotocol/sdk": "^1.7.0" }
	}`)
	writeFile(t, filepath.Join(root, "packages", "openapi-mcp-server", "src", "server.ts"), `
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

export default class OpenAPIMCPServer {
  constructor(config) {
    this.server = new Server(config.server, { capabilities: {} });
  }
}
`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if len(resolution.Targets) != 2 {
		t.Fatalf("expected exactly 2 targets, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}

	var wrapper, base *Project
	for _, p := range resolution.Projects {
		switch p.Name {
		case "@twilio-alpha/mcp":
			wrapper = p
		case "@twilio-alpha/openapi-mcp-server":
			base = p
		}
	}
	if wrapper == nil || wrapper.Role != RoleMCPServer {
		t.Errorf("expected @twilio-alpha/mcp to be promoted to RoleMCPServer, got %+v", wrapper)
	}
	if base == nil || base.Role != RoleMCPServer {
		t.Errorf("expected @twilio-alpha/openapi-mcp-server to remain RoleMCPServer (not demoted), got %+v", base)
	}
}

// TestResolve_ManifestlessPythonScriptBecomesTarget reproduces oracle/mcp's
// real dbtools-mcp-server.py end-to-end: no pyproject.toml/setup.py
// anywhere, just a script with full combined server evidence.
func TestResolve_ManifestlessPythonScriptBecomesTarget(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dbtools-mcp-server")
	writeFile(t, filepath.Join(dir, "README.md"), "# DBTools MCP Server\n")
	writeFile(t, filepath.Join(dir, "requirements.txt"), "fastmcp==3.4.2\n")
	writeFile(t, filepath.Join(dir, "dbtools-mcp-server.py"), `
from fastmcp import FastMCP

mcp = FastMCP("oci")

if __name__ == "__main__":
    mcp.run(transport='stdio')
`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected exactly 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
	if resolution.Targets[0].Name != "dbtools-mcp-server" {
		t.Errorf("expected target name 'dbtools-mcp-server', got %q", resolution.Targets[0].Name)
	}
}

// TestResolve_RemotesOnlyServerJSONIsNotATarget ensures a remotes-only
// server.json (nothing local to scan) never becomes a selectable target,
// while still being visible in Resolution.Projects rather than silently
// vanishing.
func TestResolve_RemotesOnlyServerJSONIsNotATarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "remote-server", "server.json"), `{
  "name": "com.example/remote-server",
  "remotes": [ { "type": "streamable-http", "url": "https://example.com/mcp" } ]
}`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 0 {
		t.Errorf("expected 0 targets for a remotes-only server.json, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
	found := false
	for _, p := range resolution.Projects {
		if p.Role == RoleRemoteReference {
			found = true
		}
	}
	if !found {
		t.Error("expected the remote reference to still be visible in Resolution.Projects")
	}
}

// TestResolve_JavaStandaloneServer reproduces oracle/mcp's real
// oracle-db-mcp-toolkit end-to-end: a single, standalone Maven project with
// no local dependencies.
func TestResolve_JavaStandaloneServer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pom.xml"), `<project>
  <groupId>com.oracle.database.mcptoolkit</groupId>
  <artifactId>oracle-db-mcp-toolkit</artifactId>
  <dependencies>
    <dependency>
      <groupId>io.modelcontextprotocol.sdk</groupId>
      <artifactId>mcp</artifactId>
      <version>0.12.1</version>
    </dependency>
  </dependencies>
</project>`)
	writeFile(t, filepath.Join(root, "src", "main", "java", "OracleDatabaseMCPToolkit.java"), `
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;

public class OracleDatabaseMCPToolkit {
    public static void main(String[] args) {
        var server = McpServer.sync(new StdioServerTransportProvider(null))
            .serverInfo("oracle-db-mcp-toolkit", "1.0.0")
            .build();
    }
}
`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected exactly 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
	if resolution.Targets[0].Name != "oracle-db-mcp-toolkit" {
		t.Errorf("expected target name 'oracle-db-mcp-toolkit', got %q", resolution.Targets[0].Name)
	}
}

// TestResolve_RustBinaryWrappingLibraryCrate reproduces the real
// BrowserOS shape end-to-end: browseros-mcp is a pure library crate (no
// main.rs, no binary target) that implements rmcp's ServerHandler trait;
// browseros-claw-server-rs is a binary crate (has its own fn main) that
// depends on it via a path dependency but never imports rmcp directly
// itself. Expected: exactly 1 target (the binary, promoted via
// promoteWrapperServers), with the library correctly demoted to
// RoleSharedLibrary (via demoteReachableFallbackServers -- it has no
// fn main of its own, unlike twilio-labs/mcp's base package, so it is
// *not* immune) and still included in the binary's scan scope.
func TestResolve_RustBinaryWrappingLibraryCrate(t *testing.T) {
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "browseros-mcp", "Cargo.toml"), `[package]
name = "browseros-mcp"

[dependencies]
rmcp.workspace = true
`)
	writeFile(t, filepath.Join(root, "browseros-mcp", "src", "service.rs"), `
use rmcp::handler::server::ServerHandler;

pub struct BrowserMcpService {}

impl ServerHandler for BrowserMcpService {
    fn get_info(&self) -> rmcp::model::InitializeResult {
        todo!()
    }
}
`)

	writeFile(t, filepath.Join(root, "claw-server-rust", "Cargo.toml"), `[package]
name = "browseros-claw-server-rs"

[dependencies]
browseros-mcp = { path = "../browseros-mcp" }
`)
	writeFile(t, filepath.Join(root, "claw-server-rust", "src", "main.rs"), `
fn main() {
    browseros_mcp::run_server();
}
`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected exactly 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}
	if resolution.Targets[0].Name != "browseros-claw-server-rs" {
		t.Errorf("expected target name 'browseros-claw-server-rs', got %q", resolution.Targets[0].Name)
	}

	var lib *Project
	for _, p := range resolution.Projects {
		if p.Name == "browseros-mcp" {
			lib = p
		}
	}
	if lib == nil || lib.Role != RoleSharedLibrary {
		t.Errorf("expected browseros-mcp to be demoted to RoleSharedLibrary, got %+v", lib)
	}
	if len(resolution.Targets[0].ScanRoots()) != 2 {
		t.Errorf("expected the binary's scan roots to include itself + the library, got %v", resolution.Targets[0].ScanRoots())
	}
}

// TestResolve_NestedManifestReachesScanRoot proves regression requirement 3:
// a nested manifest+lockfile physically inside the primary server's own
// directory tree, with no LocalDeps edge of its own, does not fragment
// ScanRoots() into a narrower scope -- the ancestor root SCA is handed
// already covers it via the scanner's own recursive walk (see the plan's
// grounding: internal/reposcan/sca.go passes Recursive:true).
func TestResolve_NestedManifestReachesScanRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "go.mod"), `module example.com/server

go 1.22

require github.com/modelcontextprotocol/go-sdk v1.3.1
`)
	writeFile(t, filepath.Join(root, "server", "main.go"), `package main
import "github.com/modelcontextprotocol/go-sdk/mcp"
func main() { _ = mcp.NewServer(nil, nil) }
`)
	// A nested tool with its own manifest+lockfile, no LocalDeps edge at all.
	writeFile(t, filepath.Join(root, "server", "tools", "package.json"), `{"name": "helper-tool"}`)
	writeFile(t, filepath.Join(root, "server", "tools", "package-lock.json"), `{}`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}

	roots := resolution.Targets[0].ScanRoots()
	if len(roots) != 1 {
		t.Fatalf("expected a single scan root (the nested tools/ dir has no LocalDeps edge, so it must not fragment into its own root), got %v", roots)
	}
	nestedManifestDir := filepath.Clean(filepath.Join(root, "server", "tools"))
	if !strings.HasPrefix(nestedManifestDir, roots[0]+string(filepath.Separator)) {
		t.Errorf("expected the nested manifest's directory %q to be covered by scan root %q (the input contract the SCA scanner's own recursive walk depends on)", nestedManifestDir, roots[0])
	}

	found := false
	for _, m := range DiscoveredManifests(roots) {
		if filepath.Base(m) == "package.json" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DiscoveredManifests to surface the nested package.json")
	}
}

// TestResolve_MixedLanguageNestedProjectDoesNotFragmentScanRoots proves
// regression requirement 4: a differently-classified nested project
// (Java, physically inside a Python server's own directory tree, no
// LocalDeps edge -- cross-ecosystem deps aren't expressible via any manifest
// this package parses) doesn't fragment ScanRoots() either. Its content is
// already covered by the parent root's recursive scan regardless of which
// ecosystem classified it.
func TestResolve_MixedLanguageNestedProjectDoesNotFragmentScanRoots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "pyproject.toml"), `[project]
name = "py-server"
dependencies = ["mcp"]
`)
	writeFile(t, filepath.Join(root, "server", "app.py"), `from mcp.server.lowlevel import Server
s = Server("py-server")
`)
	writeFile(t, filepath.Join(root, "server", "native-tool", "pom.xml"), `<project>
  <groupId>example</groupId>
  <artifactId>native-tool</artifactId>
</project>
`)
	writeFile(t, filepath.Join(root, "server", "native-tool", "Main.java"), `public class Main { public static void main(String[] a) {} }`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}

	roots := resolution.Targets[0].ScanRoots()
	if len(roots) != 1 {
		t.Fatalf("expected the nested Java tool to not fragment into its own scan root, got %v", roots)
	}
	nestedDir := filepath.Clean(filepath.Join(root, "server", "native-tool"))
	if !strings.HasPrefix(nestedDir, roots[0]+string(filepath.Separator)) {
		t.Errorf("expected nested Java directory %q to be covered by scan root %q", nestedDir, roots[0])
	}
}

// TestResolve_TestSiblingWithReverseDependencyIsIncludedInTargetScope is the
// end-to-end reproduction of the one real gap this phase fixes: a test
// sibling that depends ON the server (the reverse of every other edge this
// package follows) is pulled into the target's scope instead of silently
// omitted.
func TestResolve_TestSiblingWithReverseDependencyIsIncludedInTargetScope(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "package.json"), `{
  "name": "my-server",
  "dependencies": { "@modelcontextprotocol/sdk": "^1.0.0" }
}`)
	writeFile(t, filepath.Join(root, "server", "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
new McpServer();
`)
	writeFile(t, filepath.Join(root, "tests", "server.tests", "package.json"), `{
  "name": "my-server-tests",
  "dependencies": { "my-server": "file:../../server" }
}`)
	writeFile(t, filepath.Join(root, "tests", "server.tests", "index.test.js"), "// exercises my-server\n")

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(resolution.Targets), resolution.Targets)
	}

	target := resolution.Targets[0]
	if len(target.Included) != 2 {
		t.Fatalf("expected server + its test sibling included, got %d: %+v", len(target.Included), target.Included)
	}
	if len(target.ScanRoots()) != 2 {
		t.Errorf("expected 2 scan roots (server, tests/server.tests -- siblings, neither nested under the other), got %v", target.ScanRoots())
	}

	serverDir := filepath.Clean(filepath.Join(root, "server"))
	testsDir := filepath.Clean(filepath.Join(root, "tests", "server.tests"))
	if target.IncludedReasons[serverDir] != InclusionPrimary {
		t.Errorf("expected primary reason for server dir, got %v", target.IncludedReasons[serverDir])
	}
	if target.IncludedReasons[testsDir] != InclusionTestDependent {
		t.Errorf("expected test-dependent reason for the test sibling, got %v", target.IncludedReasons[testsDir])
	}
}
