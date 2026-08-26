package targetresolve

import (
	"path/filepath"
	"testing"
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
		name string
		dir  string
		want bool
	}{
		{"dotted Tests suffix", "/repo/Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests", true},
		{"tests path segment", "/repo/packages/tests/fixture-server", true},
		{"__tests__ path segment", "/repo/packages/__tests__/fixture-server", true},
		{"underscore test suffix", "/repo/packages/my_server_test", true},
		{"plain project", "/repo/packages/my-server", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Project{Dir: tc.dir}
			if got := isTestShapedProject(p); got != tc.want {
				t.Errorf("isTestShapedProject(%q) = %v, want %v", tc.dir, got, tc.want)
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
