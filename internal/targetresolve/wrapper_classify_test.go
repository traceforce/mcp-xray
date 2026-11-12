package targetresolve

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

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
	testProj := &Project{Name: "server.Tests", Dir: "/repo/server.Tests", RelDir: "server.Tests", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"test-runner"}}
	testProj.LocalDeps = []string{server.Dir}

	promoteWrapperServers([]*Project{server, testProj})

	if testProj.Role == RoleMCPServer {
		t.Errorf("expected a test-shaped project to never be promoted to RoleMCPServer, got %v", testProj.Role)
	}
}

// Wrapper promotion names the server its dependency closure reaches. With
// several reachable servers, the name must not depend on Go's randomized map
// iteration order: --list-targets output (including --json) has to be
// identical from run to run.
func TestPromoteWrapperServers_EvidenceIsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "wrapper",
		"bin": "./cli.js",
		"dependencies": {"server-c": "workspace:*", "server-a": "workspace:*", "server-d": "workspace:*", "server-b": "workspace:*"}
	}`)
	for _, name := range []string{"server-a", "server-b", "server-c", "server-d"} {
		writeFile(t, filepath.Join(root, "servers", name, "package.json"), `{"name": "`+name+`", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
		writeFile(t, filepath.Join(root, "servers", name, "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	}

	var first string
	for run := 0; run < 20; run++ {
		resolution, err := Resolve(root)
		if err != nil {
			t.Fatal(err)
		}
		var evidence string
		for _, p := range resolution.Projects {
			if p.Name == "wrapper" {
				evidence = strings.Join(p.Evidence, "; ")
			}
		}
		if run == 0 {
			first = evidence
			if !strings.Contains(first, "wrapper/composed MCP server") {
				t.Fatalf("wrapper was not promoted; evidence = %q", first)
			}
		} else if evidence != first {
			t.Fatalf("run %d evidence differs:\n  %q\nvs\n  %q", run, evidence, first)
		}
	}
}

// A Cloudflare Worker that serves a workspace library's MCP server is a
// wrapper: its Wrangler configuration declares the entry module it runs.
func TestPromoteWrapperServers_WorkerEntrypoint(t *testing.T) {
	root := t.TempDir()
	server := &Project{Name: "mcp-common", Dir: filepath.Join(root, "packages", "common"), Ecosystem: "node", Role: RoleMCPServer}
	worker := &Project{Name: "radar", Dir: filepath.Join(root, "apps", "radar"), Ecosystem: "node", Role: RoleUnrelated}
	worker.LocalDeps = []string{server.Dir}
	writeFile(t, filepath.Join(worker.Dir, "wrangler.jsonc"), "{\n\t// the Worker\n\t\"name\": \"radar\",\n\t\"main\": \"src/radar.app.ts\"\n}\n")

	promoteWrapperServers([]*Project{server, worker})

	if worker.Role != RoleMCPServer {
		t.Errorf("worker role = %v, want it promoted", worker.Role)
	}
	writeFile(t, filepath.Join(root, "toml", "wrangler.toml"), "name = \"x\"\nmain = \"src/index.ts\"\n")
	if !hasWorkerEntrypoint(&Project{Dir: filepath.Join(root, "toml")}) {
		t.Error("a wrangler.toml with main is a Worker entrypoint")
	}
	writeFile(t, filepath.Join(root, "nomain", "wrangler.toml"), "name = \"x\"\n")
	if hasWorkerEntrypoint(&Project{Dir: filepath.Join(root, "nomain")}) {
		t.Error("a Wrangler configuration without main declares no entrypoint")
	}
}

// A client of a server (a test client or benchmark that launches it) is not
// a wrapper of it, however launchable it is.
func TestPromoteWrapperServers_ClientWithClientCodeIsNotPromoted(t *testing.T) {
	root := t.TempDir()
	server := &Project{Name: "server", Dir: filepath.Join(root, "server"), Ecosystem: "node", Role: RoleMCPServer}
	client := &Project{Name: "test-client", Dir: filepath.Join(root, "test-client"), Ecosystem: "node", Role: RoleMCPClient, BinNames: []string{"test-client"}}
	client.LocalDeps = []string{server.Dir}
	writeFile(t, filepath.Join(client.Dir, "index.ts"), `import { Client } from "@modelcontextprotocol/sdk/client/index.js";`+"\n")

	promoteWrapperServers([]*Project{server, client})

	if client.Role != RoleMCPClient {
		t.Errorf("client role = %v, want it left a client", client.Role)
	}
}

// A dependency the project needs only for development (a Python dependency
// group) does not make it a wrapper of the server it pulls in.
func TestPromoteWrapperServers_DevelopmentDependencyDoesNotPromote(t *testing.T) {
	root := t.TempDir()
	examplesDir := filepath.Join(root, "examples")
	writeFile(t, filepath.Join(root, "src", "cli.py"), "def main():\n    app.run()\n")
	server := &Project{Name: "examples", Dir: examplesDir, Ecosystem: "python", Role: RoleMCPServer}
	sdk := &Project{Name: "mcp", Dir: root, Ecosystem: "python", Role: RoleUnrelated}
	sdk.LocalDeps = []string{server.Dir}

	promoteWrapperServers([]*Project{server, sdk})
	if sdk.Role != RoleMCPServer {
		t.Fatalf("role = %v; with a runtime dependency the fixture must promote, or the test proves nothing", sdk.Role)
	}

	sdk.Role, sdk.Evidence = RoleUnrelated, nil
	sdk.DevLocalDeps = []string{server.Dir}
	promoteWrapperServers([]*Project{server, sdk})
	if sdk.Role != RoleUnrelated {
		t.Errorf("role = %v, want unrelated: the server is only a development dependency", sdk.Role)
	}
}

// A deployed Worker that also talks to MCP servers as a client (a chat UI
// next to the hosted server) is still a wrapper of the server it serves.
func TestPromoteWrapperServers_WorkerWithClientCodeIsPromoted(t *testing.T) {
	root := t.TempDir()
	core := &Project{Name: "core", Dir: filepath.Join(root, "core"), Ecosystem: "node", Role: RoleMCPServer}
	worker := &Project{Name: "hosted", Dir: filepath.Join(root, "hosted"), Ecosystem: "node", Role: RoleMCPClient}
	worker.LocalDeps = []string{core.Dir}
	writeFile(t, filepath.Join(worker.Dir, "wrangler.jsonc"), `{"main": "src/index.ts"}`)
	writeFile(t, filepath.Join(worker.Dir, "src", "chat.ts"), `import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";`+"\n")

	promoteWrapperServers([]*Project{core, worker})

	if worker.Role != RoleMCPServer {
		t.Errorf("role = %v, want the Worker promoted", worker.Role)
	}
}

func TestHasWorkerEntrypoint(t *testing.T) {
	cases := []struct {
		name, file, content string
		want                bool
	}{
		{"JSONC with comments and trailing commas", "wrangler.jsonc", "{\n  // entry\n  \"name\": \"x\", /* \"main\": \"no\" */\n  \"main\": \"src/index.ts\",\n}\n", true},
		{"one-line JSON", "wrangler.json", `{"name":"x","main":"src/index.ts"}`, true},
		{"main only for an environment", "wrangler.toml", "name = \"x\"\n[env.production]\nmain = \"src/index.ts\"\n", true},
		{"TOML", "wrangler.toml", "name = \"x\"\nmain = \"src/index.ts\"\n", true},
		{"main in [vars] is a variable", "wrangler.toml", "name = \"x\"\n[vars]\nmain = \"production\"\n", false},
		{"main only in a comment", "wrangler.jsonc", "{\n  /* \"main\": \"src/index.ts\" */\n  \"name\": \"x\"\n}\n", false},
		{"a URL in a string is not a comment", "wrangler.jsonc", `{"name": "x", "route": "https://example.com/*", "main": "src/index.ts"}`, true},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, tc.file), tc.content)
		if got := hasWorkerEntrypoint(&Project{Dir: dir}); got != tc.want {
			t.Errorf("%s: hasWorkerEntrypoint = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A script launches a server only when a runner runs a file of the project
// that starts a server: not a build, test or client script, not a file
// outside the project, and not an unparsable script value.
func TestNodeScriptStartsServer(t *testing.T) {
	const server = "import { serveStdio } from \"@modelcontextprotocol/server/stdio\";\nvoid serveStdio(buildServer);\n"
	const client = "import { Client } from \"@modelcontextprotocol/client\";\nawait client.connect(transport);\n"
	// A build entry can start a server too; what tells it apart is that
	// esbuild bundles it rather than runs it.
	const library = "import { McpServer } from \"@modelcontextprotocol/server\";\nexport const start = (s, transport) => s.connect(transport);\n"
	cases := []struct {
		name, scripts string
		want          bool
	}{
		{"tsx runs the server", `{"start": "tsx server.ts"}`, true},
		{"node behind env and npx", `{"start": "cross-env PORT=1 npx tsx ./server.ts --http"}`, true},
		{"a build entry is not run", `{"build": "esbuild src/entry.ts --bundle"}`, false},
		{"a client script", `{"client": "tsx client.ts"}`, false},
		{"a file outside the project", `{"start": "tsx ../other/server.ts"}`, false},
		{"npm comment keys are skipped", `{"//": ["run with npm start"], "start": "tsx server.ts"}`, true},
		{"a test's server is not the program's", `{"test:e2e": "tsx test/server.ts"}`, false},
	}
	for _, tc := range cases {
		root := t.TempDir()
		dir := filepath.Join(root, "app")
		writeFile(t, filepath.Join(dir, "package.json"), `{"name": "app", "scripts": `+tc.scripts+`}`)
		writeFile(t, filepath.Join(dir, "server.ts"), server)
		writeFile(t, filepath.Join(dir, "test", "server.ts"), server)
		writeFile(t, filepath.Join(dir, "client.ts"), client)
		writeFile(t, filepath.Join(dir, "src", "entry.ts"), library)
		writeFile(t, filepath.Join(root, "other", "server.ts"), server)
		p := &Project{Dir: dir, ManifestPath: filepath.Join(dir, "package.json"), Ecosystem: "node"}
		if got := nodeScriptStartsServer(p, []*Project{p}); got != tc.want {
			t.Errorf("%s: nodeScriptStartsServer = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestJSONCToJSON(t *testing.T) {
	in := "\xef\xbb\xbf{\n  \"a\": \"x\\\" // not a comment\", // comment\n  \"b\": [1, 2,],\n}"
	var got map[string]interface{}
	if err := json.Unmarshal(jsoncToJSON([]byte(in)), &got); err != nil {
		t.Fatalf("jsoncToJSON produced invalid JSON: %v (%q)", err, jsoncToJSON([]byte(in)))
	}
	if got["a"] != `x" // not a comment` {
		t.Errorf("a = %q; an escaped quote must not end the string", got["a"])
	}
}

// A dependency on a directory that also holds another ecosystem's project (a
// pyproject.toml of tool settings beside the package.json) still reaches the
// package the wrapper depends on.
func TestPromoteWrapperServers_DependencyDirectorySharedWithAnotherEcosystem(t *testing.T) {
	coreNode := &Project{Name: "core-server", Dir: "/repo/core", Ecosystem: "node", Role: RoleMCPServer}
	corePython := &Project{Name: "core-py", Dir: "/repo/core", Ecosystem: "python", Role: RoleUnrelated}
	cli := &Project{Name: "cli", Dir: "/repo/cli", Ecosystem: "node", Role: RoleUnrelated, BinNames: []string{"cli"}}
	cli.LocalDeps = []string{coreNode.Dir}

	promoteWrapperServers([]*Project{cli, coreNode, corePython})

	if cli.Role != RoleMCPServer {
		t.Errorf("cli role = %v, want mcp-server (a wrapper of core-server)", cli.Role)
	}
}

// Entrypoint evidence means the program starts a server, not that some
// method named run, connect or listen is called: a test's t.Run, an
// exec.Cmd, a database connection, a mock server, a subprocess or a command
// handler's RunAsync are no startup.
func TestHasOwnEntrypointEvidence(t *testing.T) {
	cases := []struct {
		name, ecosystem, file, source string
		want                          bool
	}{
		{"go main running the server", "go", "main.go", "package main\n\nfunc main() {\n\tif err := core.New().Run(context.Background(), &mcp.StdioTransport{}); err != nil {\n\t\tpanic(err)\n\t}\n}\n", true},
		{"go cobra command running the server", "go", "main.go", "package main\n\nfunc main() {\n\troot := &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error {\n\t\treturn core.New().Run(cmd.Context(), &mcp.StdioTransport{})\n\t}}\n\troot.Execute()\n}\n", true},
		{"go main serving HTTP", "go", "main.go", "package main\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", core.Handler())\n}\n", true},
		{"go main running a command", "go", "main.go", "package main\n\nfunc main() {\n\texec.Command(\"go\", \"generate\").Run()\n}\n", false},
		{"go library running a server", "go", "serve.go", "package core\n\nfunc Serve(ctx context.Context, s *mcp.Server) error {\n\treturn s.Run(ctx, &mcp.StdioTransport{})\n}\n", false},
		{"go test helper", "go", "testutil.go", "package main\n\nfunc main() {}\n\nfunc check(t *testing.T) {\n\tt.Run(\"paris\", func(t *testing.T) {})\n}\n", false},
		{"node server on a transport", "node", "index.ts", "await server.connect(new StdioServerTransport());\n", true},
		{"node HTTP server", "node", "index.ts", "app.listen(PORT, () => console.log(\"up\"));\n", true},
		{"node database connection", "node", "db.ts", "await pool.connect();\nawait mongoose.connect(uri);\n", false},
		{"node mock server", "node", "start.ts", "mswServer.listen({\n  onUnhandledRequest: (req, print) => print.warning(),\n});\n", false},
		{"python server run", "python", "server.py", "mcp.run(transport=\"stdio\")\n", true},
		{"python async main", "python", "server.py", "asyncio.run(main())\n", true},
		{"python subprocess and agent", "python", "tool.py", "subprocess.run([\"git\", \"status\"])\nresult = agent.run(prompt)\n", false},
		{".NET host", "dotnet", "Program.cs", "await builder.Build().RunAsync();\n", true},
		{".NET web application", "dotnet", "Program.cs", "var app = builder.Build();\napp.MapMcp();\napp.Run();\n", true},
		{".NET command handler", "dotnet", "RunPipelineCommand.cs", "var result = await _handler.RunAsync(workspaceId, pipelineId);\nawait Task.Run(() => Work());\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, tc.file), tc.source)
			p := &Project{Name: "p", Dir: dir, Ecosystem: tc.ecosystem}
			if got := hasOwnEntrypointEvidence(p, []*Project{p}); got != tc.want {
				t.Errorf("hasOwnEntrypointEvidence = %v, want %v", got, tc.want)
			}
		})
	}
}

// A .NET tool whose command calls a handler's RunAsync is not a program
// wrapping the core server it references, so the core stays the target.
func TestResolve_CommandHandlerRunIsNotAWrapperEntrypoint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "core", "Core.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="ModelContextProtocol" /></ItemGroup></Project>`)
	writeFile(t, filepath.Join(root, "core", "Ext.cs"), "public static class Ext { public static void Register(IServiceCollection s) { s.AddMcpServer(); } }\n")
	writeFile(t, filepath.Join(root, "tools", "Pipelines", "Pipelines.csproj"), `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="..\\..\\core\\Core.csproj" /></ItemGroup></Project>`)
	writeFile(t, filepath.Join(root, "tools", "Pipelines", "RunPipelineCommand.cs"), "public class RunPipelineCommand { public async Task Exec() { var r = await _handler.RunAsync(workspaceId, pipelineId); } }\n")

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if names := targetNames(resolution.Targets); len(names) != 1 || names[0] != "Core" {
		t.Errorf("targets = %v, want only Core", names)
	}
}
