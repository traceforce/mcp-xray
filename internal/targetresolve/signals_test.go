package targetresolve

import (
	"path/filepath"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestClassifyGoProject_Server(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module github.com/example/my-server

go 1.22

require github.com/modelcontextprotocol/go-sdk v1.3.1
`)
	writeFile(t, filepath.Join(root, "main.go"), `package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

func main() {
	_ = mcp.NewServer(nil, nil)
}
`)
	p, err := newGoProject(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("newGoProject error: %v", err)
	}
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyGoProject_Client(t *testing.T) {
	// Mirrors mcp-xray's own repository: depends on the Go SDK, calls
	// mcp.NewClient, never mcp.NewServer -- the built-in real-world negative
	// case described in the plan.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module github.com/example/my-scanner

go 1.22

require github.com/modelcontextprotocol/go-sdk v1.3.1
`)
	writeFile(t, filepath.Join(root, "main.go"), `package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

func main() {
	_ = mcp.NewClient(nil, nil)
}
`)
	p, err := newGoProject(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("newGoProject error: %v", err)
	}
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleMCPClient {
		t.Errorf("expected RoleMCPClient, got %v", role)
	}
}

func TestClassifyGoProject_NoSDKIsUnrelated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module github.com/example/other\n\ngo 1.22\n")
	p, _ := newGoProject(filepath.Join(root, "go.mod"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated, got %v", role)
	}
}

func TestClassifyNodeProject_Server(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "node-server",
		"dependencies": { "@modelcontextprotocol/sdk": "^1.0.0" }
	}`)
	writeFile(t, filepath.Join(root, "index.ts"), `
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "x", version: "1.0" });
`)
	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyPythonProject_FastMCPServer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `[project]
name = "py-server"
dependencies = ["fastmcp>=2.0"]
`)
	writeFile(t, filepath.Join(root, "server.py"), `
from fastmcp import FastMCP
mcp = FastMCP("my server")
`)
	p, _ := newPythonProject(filepath.Join(root, "pyproject.toml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestConsumerOrUnrelated_ConsumerConfigOnly(t *testing.T) {
	// Pattern 7: a project with an MCP client config (mcp.json) but no MCP
	// SDK dependency of its own must never be classified as a server.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "regular-app"}`)
	writeFile(t, filepath.Join(root, ".cursor", "mcp.json"), `{"mcpServers": {"github": {"command": "npx", "args": ["-y", "some-mcp"]}}}`)

	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleConsumerConfigOnly {
		t.Errorf("expected RoleConsumerConfigOnly, got %v (evidence: %v)", role, evidence)
	}
}

func TestConsumerOrUnrelated_PlainProjectIsUnrelated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "regular-app"}`)

	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated, got %v", role)
	}
}

func TestConsumerOrUnrelated_FilenameAloneIsNotEnough(t *testing.T) {
	// A file merely named mcp.json that isn't actually MCP client config
	// (no "mcpServers" key) must not trigger RoleConsumerConfigOnly.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "regular-app"}`)
	writeFile(t, filepath.Join(root, "mcp.json"), `{"unrelated": true}`)

	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated for a same-named but non-MCP config file, got %v", role)
	}
}

func TestClassifyDotnetProject_ServerViaWrapperMethod(t *testing.T) {
	// Reproduces the real microsoft/mcp repo: the server calls a
	// repo-specific wrapper (AddAzureMcpServer), not the official SDK's own
	// AddMcpServer() directly. The pattern must match structurally
	// (Add<anything>McpServer() preceded by a `.`) without hardcoding either
	// name.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Fabric.Mcp.Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(root, "Program.cs"), `
var builder = Host.CreateApplicationBuilder();
builder.Services.AddAzureMcpServer(new() { Transport = TransportTypes.StdIo });
`)
	p, _ := newDotnetProject(filepath.Join(root, "Fabric.Mcp.Server.csproj"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyDotnetProject_DefinitionSiteDoesNotCountAsACall(t *testing.T) {
	// The method *definition* of a wrapper like AddAzureMcpServer must not
	// itself be mistaken for a call site -- no `.` immediately precedes the
	// name there (it's preceded by the return type instead).
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Core.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(root, "ServiceCollectionExtensions.cs"), `
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAzureMcpServer(this IServiceCollection services, ServerStartOptions options)
    {
        return services;
    }
}
`)
	p, _ := newDotnetProject(filepath.Join(root, "Core.csproj"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleMCPClient {
		t.Errorf("expected a method definition alone (no call site) to default to RoleMCPClient, got %v", role)
	}
}

func TestClassifyDotnetProject_RealSDKCallAlsoMatches(t *testing.T) {
	// The official SDK's own AddMcpServer() call, unwrapped, must also match
	// -- the pattern isn't tied to any one vendor's wrapper name.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol.AspNetCore" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(root, "Program.cs"), `
builder.Services.AddMcpServer().WithStdioServerTransport();
`)
	p, _ := newDotnetProject(filepath.Join(root, "Server.csproj"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer for the unwrapped official SDK call, got %v", role)
	}
}

func TestClassifyDotnetProject_NoSDKIsUnrelated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Other.csproj"), `<Project Sdk="Microsoft.NET.Sdk"></Project>`)
	p, _ := newDotnetProject(filepath.Join(root, "Other.csproj"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated, got %v", role)
	}
}

func TestClassifyPythonProject_LowlevelServerAPI(t *testing.T) {
	// Reproduces awslabs/mcp's healthlake-mcp-server: uses the low-level
	// mcp.server.lowlevel.Server API directly, never calls FastMCP(...).
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `[project]
name = "healthlake-mcp-server"
dependencies = ["mcp>=1.23.0"]
`)
	writeFile(t, filepath.Join(root, "server.py"), `
from mcp.server.lowlevel import Server

server = Server("healthlake")
`)
	p, _ := newPythonProject(filepath.Join(root, "pyproject.toml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyPythonProject_FastMCPSubclass(t *testing.T) {
	// Reproduces awslabs/mcp's s3-tables-mcp-server: subclasses FastMCP
	// rather than calling it directly.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `[project]
name = "s3-tables-mcp-server"
dependencies = ["mcp[cli]==1.23.0"]
`)
	writeFile(t, filepath.Join(root, "server.py"), `
from fastmcp import FastMCP

class S3TablesMCP(FastMCP):
    pass
`)
	p, _ := newPythonProject(filepath.Join(root, "pyproject.toml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyPythonProject_FastMCPClientImportIsNotServerEvidence(t *testing.T) {
	// A bare `from fastmcp import Client` must not count as server evidence
	// -- fastmcp's top-level module exports both FastMCP (server) and
	// Client (client), so a bare-module import can't disambiguate
	// direction; only the mcp.server/mcp.client namespace imports can.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `[project]
name = "py-client"
dependencies = ["fastmcp>=2.0"]
`)
	writeFile(t, filepath.Join(root, "client.py"), `
from fastmcp import Client

async def main():
    async with Client("server.py") as client:
        await client.ping()
`)
	p, _ := newPythonProject(filepath.Join(root, "pyproject.toml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPClient {
		t.Errorf("expected RoleMCPClient, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyNodeProject_SubclassWithoutBareConstructorCall(t *testing.T) {
	// Reproduces microsoft/rushstack's @rushstack/mcp-server: subclasses
	// McpServer, never calls `new McpServer(...)` anywhere.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "@rushstack/mcp-server",
		"dependencies": { "@modelcontextprotocol/sdk": "~1.10.2" }
	}`)
	writeFile(t, filepath.Join(root, "server.ts"), `
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export class RushMCPServer extends McpServer {}
`)
	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyDotnetProject_UsingDirectiveAloneIsServerEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Server.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(root, "Program.cs"), `
using ModelContextProtocol.Server;

// no .Add*McpServer( call anywhere in this file
`)
	p, _ := newDotnetProject(filepath.Join(root, "Server.csproj"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestIsTestShapedProject(t *testing.T) {
	cases := []struct {
		name   string
		dir    string
		relDir string
		want   bool
	}{
		{"dotted Tests suffix", "/repo/Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests", "Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests", true},
		{"tests path segment", "/repo/packages/tests/fixture-server", "packages/tests/fixture-server", true},
		{"__tests__ path segment", "/repo/packages/__tests__/fixture-server", "packages/__tests__/fixture-server", true},
		{"underscore test suffix", "/repo/packages/my_server_test", "packages/my_server_test", true},
		{"plain project", "/repo/packages/my-server", "packages/my-server", false},
		// The checkout's own location must never matter.
		{"checkout under a tests ancestor", "/home/ci/tests/repo/packages/my-server", "packages/my-server", false},
		{"checkout under a __tests__ ancestor", "/work/__tests__/repo/server", "server", false},
		{"repository root named like a test project", "/home/ci/my_server_test", ".", false},
		// Without a repository-relative location only the project's own
		// directory name is trusted.
		{"unknown relDir keeps own-name suffix check", "/repo/Foo.Tests", "", true},
		{"unknown relDir ignores ancestor segments", "/repo/tests/server", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Project{Dir: tc.dir, RelDir: tc.relDir}
			if got := isTestShapedProject(p); got != tc.want {
				t.Errorf("isTestShapedProject(dir=%q, relDir=%q) = %v, want %v", tc.dir, tc.relDir, got, tc.want)
			}
		})
	}
}

func TestClassifyProject_TestShapedProjectNeverBecomesServer(t *testing.T) {
	// Reproduces the real microsoft/mcp phantom-target bug: a .Tests project
	// legitimately constructs a real server in its integration tests.
	root := t.TempDir()
	testDir := filepath.Join(root, "Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests")
	writeFile(t, filepath.Join(testDir, "Tests.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="ModelContextProtocol" />
  </ItemGroup>
</Project>`)
	writeFile(t, filepath.Join(testDir, "IntegrationTests.cs"), `
builder.Services.AddMcpServer().WithStdioServerTransport();
`)
	p, _ := newDotnetProject(filepath.Join(testDir, "Tests.csproj"))
	role, evidence := classifyProject(p, []*Project{p})
	if role == RoleMCPServer {
		t.Errorf("expected a test-shaped project to never classify as RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

func TestClassifyJavaProject_Server(t *testing.T) {
	// Reproduces oracle/mcp's real oracle-db-mcp-toolkit.
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
	p, _ := newJavaProject(filepath.Join(root, "pom.xml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

// A library whose tests start a server is not a server: java-sdk's
// JSON-mapper jar was a target because its integration tests build one.
func TestClassifyJavaProject_TestsAreNotServerEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>mcp-json-mapper</artifactId>
  <dependencies>
    <dependency>
      <groupId>io.modelcontextprotocol.sdk</groupId>
      <artifactId>mcp</artifactId>
    </dependency>
  </dependencies>
</project>`)
	writeFile(t, filepath.Join(root, "src", "main", "java", "JsonMapper.java"), "public class JsonMapper {}\n")
	writeFile(t, filepath.Join(root, "src", "test", "java", "ServerIntegrationTests.java"), `
import io.modelcontextprotocol.server.McpServer;

class ServerIntegrationTests {
    void start() { McpServer.sync(transport).build(); }
}
`)
	p, _ := newJavaProject(filepath.Join(root, "pom.xml"))
	if role, evidence := classifyProject(p, []*Project{p}); role == RoleMCPServer {
		t.Errorf("role = %v, want no server: only its tests start one (evidence: %v)", role, evidence)
	}
}

func TestClassifyJavaProject_NoSDKIsUnrelated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pom.xml"), `<project>
  <groupId>com.example</groupId>
  <artifactId>other</artifactId>
</project>`)
	p, _ := newJavaProject(filepath.Join(root, "pom.xml"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated, got %v", role)
	}
}

func TestClassifyRustProject_Server(t *testing.T) {
	// Reproduces BrowserOS's real browseros-mcp crate.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), `[package]
name = "browseros-mcp"

[dependencies]
rmcp.workspace = true
`)
	writeFile(t, filepath.Join(root, "src", "service.rs"), `
use rmcp::{handler::server::ServerHandler};

pub struct BrowserMcpService {}

impl ServerHandler for BrowserMcpService {
    fn get_info(&self) -> rmcp::model::InitializeResult {
        todo!()
    }
}
`)
	p, _ := newRustProject(filepath.Join(root, "Cargo.toml"))
	role, evidence := classifyProject(p, []*Project{p})
	if role != RoleMCPServer {
		t.Errorf("expected RoleMCPServer, got %v (evidence: %v)", role, evidence)
	}
}

// rmcp servers found in modelcontextprotocol/rust-sdk: a binary under
// src/bin (Cargo's convention, though "bin" is a build output elsewhere),
// and a library whose server impl #[tool_router(server_handler)] generates.
func TestClassifyRustProject_ServerShapes(t *testing.T) {
	cases := []struct {
		name, file, source string
		want               Role
	}{
		{"server binary under src/bin", "src/bin/server.rs", "use rmcp::{\n    ErrorData, RoleServer, ServerHandler,\n};\nimpl ServerHandler for Conformance {}\n", RoleMCPServer},
		{"impl generated by tool_router", "src/calculator.rs", "use rmcp::{\n    handler::server::wrapper::{Json, Parameters},\n    schemars, tool, tool_router,\n};\n#[tool_router(server_handler)]\nimpl Calculator {}\n", RoleMCPServer},
		{"flat handler::server path", "src/lib.rs", "use rmcp::handler::server::router::tool::ToolRouter;\n", RoleMCPServer},
		{"client handler module", "src/main.rs", "use rmcp::{handler::client::ClientHandler, ServiceExt};\n", RoleMCPClient},
		{"tool_router attribute alone", "src/calculator.rs", "use rmcp::{schemars, tool, tool_router};\n#[tool_router(server_handler)]\nimpl Calculator {}\n", RoleMCPServer},
		{"grouped handler::server import alone", "src/lib.rs", "use rmcp::{handler::server::wrapper::Parameters, schemars};\n", RoleMCPServer},
		{"binary outside src stays a build output", "bin/server.rs", "impl ServerHandler for Conformance {}\n", RoleMCPClient},
	}
	for _, tc := range cases {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname = \"x\"\n\n[dependencies]\nrmcp = \"0.8\"\n")
		writeFile(t, filepath.Join(root, filepath.FromSlash(tc.file)), tc.source)
		p, _ := newRustProject(filepath.Join(root, "Cargo.toml"))
		if role, evidence := classifyProject(p, []*Project{p}); role != tc.want {
			t.Errorf("%s: role = %v, want %v (evidence: %v)", tc.name, role, tc.want, evidence)
		}
	}
}

func TestClassifyRustProject_NoSDKIsUnrelated(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), `[package]
name = "other"

[dependencies]
serde = "1.0"
`)
	p, _ := newRustProject(filepath.Join(root, "Cargo.toml"))
	role, _ := classifyProject(p, []*Project{p})
	if role != RoleUnrelated {
		t.Errorf("expected RoleUnrelated, got %v", role)
	}
}

func TestPep508PackageName(t *testing.T) {
	cases := map[string]string{
		"fastmcp>=2.0":                   "fastmcp",
		"mcp[cli]==1.2":                  "mcp",
		"requests":                       "requests",
		"mcp ; python_version >= '3.10'": "mcp",
	}
	for spec, want := range cases {
		if got := pep508PackageName(spec); got != want {
			t.Errorf("pep508PackageName(%q) = %q, want %q", spec, got, want)
		}
	}
}

// SDK v2 publishes the server and client as their own packages; depending
// on and importing @modelcontextprotocol/server is server evidence, while a
// reference server such as @modelcontextprotocol/server-everything is not.
func TestClassifyNodeProject_SplitSDKPackages(t *testing.T) {
	cases := []struct {
		name, deps, source string
		want               Role
	}{
		{"v2 server", `{"@modelcontextprotocol/server": "^2.0.0"}`, `import { McpServer } from "@modelcontextprotocol/server";`, RoleMCPServer},
		{"v2 client", `{"@modelcontextprotocol/client": "^2.0.0"}`, `import { Client } from "@modelcontextprotocol/client";`, RoleMCPClient},
		{"reference server dependency", `{"@modelcontextprotocol/server-everything": "^1.0.0"}`, `import "@modelcontextprotocol/server-everything";`, RoleUnrelated},
		{"client-only SDK with an unrelated Server class", `{"@modelcontextprotocol/client": "^2.0.0"}`, `const io = new Server(httpServer);`, RoleMCPClient},
		{"client launching a reference server", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, `import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"; const pkg = "@modelcontextprotocol/server-everything";`, RoleMCPClient},
		{"client requiring a reference server's manifest", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, `import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"; const { bin } = require("@modelcontextprotocol/server-filesystem/package.json");`, RoleMCPClient},
		{"server imported across lines", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, "import {\n  McpServer,\n} from '@modelcontextprotocol/sdk/server/mcp.js';", RoleMCPServer},
		{"server required", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, `const { Server } = require("@modelcontextprotocol/sdk/server/index.js");`, RoleMCPServer},
		{"server imported dynamically", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, "const m = await import(`@modelcontextprotocol/sdk/server/mcp.js`);", RoleMCPServer},
		{"server re-exported", `{"@modelcontextprotocol/server": "^2.0.0"}`, `export { McpServer } from "@modelcontextprotocol/server";`, RoleMCPServer},
		// A script listing the SDK packages it watches does not use them.
		{"package name in a string list", `{"@modelcontextprotocol/sdk": "^1.0.0"}`, `const watched = [\n  "@modelcontextprotocol/server",\n  "@modelcontextprotocol/client",\n];`, RoleMCPClient},
	}
	for _, tc := range cases {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "package.json"), `{"name": "app", "dependencies": `+tc.deps+`}`)
		writeFile(t, filepath.Join(root, "index.ts"), tc.source+"\n")
		p, _ := newNodeProject(filepath.Join(root, "package.json"))
		if role, evidence := classifyProject(p, []*Project{p}); role != tc.want {
			t.Errorf("%s: role = %v, want %v (evidence: %v)", tc.name, role, tc.want, evidence)
		}
	}
}

// The SDK's own packages depend on one another; the SDK is not a user of
// itself.
func TestClassifyNodeProject_SDKPackageIsNotItsOwnUser(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "@modelcontextprotocol/sdk", "dependencies": {"@modelcontextprotocol/server": "workspace:*"}}`)
	writeFile(t, filepath.Join(root, "index.ts"), `export * from "@modelcontextprotocol/server";`+"\n")
	p, _ := newNodeProject(filepath.Join(root, "package.json"))
	if role, evidence := classifyProject(p, []*Project{p}); role != RoleUnrelated {
		t.Errorf("role = %v, want unrelated (evidence: %v)", role, evidence)
	}
}

func TestPythonSDKDependency(t *testing.T) {
	cases := []struct {
		name, pyproject, want string
	}{
		{"PEP 621 dependency", "[project]\nname = \"s\"\ndependencies = [\"fastmcp>=2.0\"]\n", "fastmcp"},
		{"extra only", "[project]\nname = \"s\"\ndependencies = [\"httpx\"]\n\n[project.optional-dependencies]\nmcp = [\"mcp>=1.2\"]\n", "mcp"},
		{"Poetry group", "[tool.poetry]\nname = \"s\"\n\n[tool.poetry.group.server.dependencies]\nFastMCP = \"^2.0\"\n", "fastmcp"},
		{"both SDKs", "[tool.poetry]\nname = \"s\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nfastmcp = \"^2.0\"\nhttpx = \"*\"\nmcp = \"^1.0\"\nrich = \"*\"\n", "mcp"},
		{"neither", "[project]\nname = \"s\"\ndependencies = [\"mcp-proxy\"]\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]interface{}
			if err := toml.Unmarshal([]byte(tc.pyproject), &doc); err != nil {
				t.Fatal(err)
			}
			// Map iteration order varies from run to run; so must not the answer.
			for range 20 {
				if got, _ := pythonSDKDependency(doc); got != tc.want {
					t.Fatalf("pythonSDKDependency = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
