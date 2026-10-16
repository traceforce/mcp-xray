package targetresolve

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"mcpxray/internal/aggregation"
)

// nodeSDKPackages are the official TypeScript SDK's packages: the original
// single package, and the separate server and client packages of SDK v2.
// nodeSDKDependency names the first one a project depends on, so a project
// that depends on the client package is client-only (clientOnlySDKs) only
// when it depends on neither of the others.
var nodeSDKPackages = []string{"@modelcontextprotocol/sdk", "@modelcontextprotocol/server", "@modelcontextprotocol/client"}

const (
	goSDKModulePath        = "github.com/modelcontextprotocol/go-sdk"
	dotnetSDKPackagePrefix = "ModelContextProtocol"
	javaSDKGroupID         = "io.modelcontextprotocol.sdk"
	rustSDKCrateName       = "rmcp"
)

var (
	// Each server/client pattern matches either a construction call or an
	// import of the SDK's server (resp. client) namespace, so a server that
	// subclasses or wraps the SDK type is found as well as one that calls
	// its constructor. Patterns are qualified with the SDK's own identifiers
	// (mcp.NewServer, not a bare NewServer) and are only checked against
	// projects whose manifest declares the matching SDK, which keeps false
	// positives down. Import aliasing (`import s "github.com/.../mcp"`)
	// evades them: an accepted limit of a regex signal.
	//
	// Go is call-syntax-only: its SDK has no separate server and client
	// packages to import.
	goServerPattern = regexp.MustCompile(`mcp\.NewServer\(`)
	goClientPattern = regexp.MustCompile(`mcp\.NewClient\(`)

	// Node: a construction call, or an import of the SDK's server (resp.
	// client) module however the imported symbol is then used -- `class
	// RushMCPServer extends McpServer` never calls `new McpServer(...)`. The
	// module is @modelcontextprotocol/sdk's server sub-path or SDK v2's
	// @modelcontextprotocol/server package (never a reference server such as
	// @modelcontextprotocol/server-everything), and it counts only as the
	// specifier of an `import ... from`, `export ... from`, `import(...)` or
	// `require(...)`: a script that merely lists the package name in a string
	// does not use it.
	nodeServerPattern = regexp.MustCompile(`new\s+(McpServer|Server)\s*\(|` + nodeModuleSpecifier(`@modelcontextprotocol/(?:sdk/)?server(?:/[^"'\x60]*)?`))
	nodeClientPattern = regexp.MustCompile(`new\s+Client\s*\(|` + nodeModuleSpecifier(`@modelcontextprotocol/(?:sdk/)?client(?:/[^"'\x60]*)?`))

	// Python: the sub-signals are also used on their own by
	// classifyPythonScriptProject for manifest-less scripts.
	//
	// The namespace patterns match only the official mcp package's
	// mcp.server/mcp.client subpackages, never a bare `import fastmcp`: the
	// standalone fastmcp package exports both FastMCP (server) and Client
	// from its top level, so that import does not say which side it is.
	pythonServerNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.server(?:\.\w+)*\s+import\b|\bimport\s+mcp\.server(?:\.\w+)*\b`)
	pythonClientNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.client(?:\.\w+)*\s+import\b|\bimport\s+mcp\.client(?:\.\w+)*\b`)
	// pythonServerConstructionPattern matches a FastMCP(...) call or a class
	// subclassing FastMCP (class Foo(FastMCP): ...), which never calls it.
	pythonServerConstructionPattern = regexp.MustCompile(`FastMCP\s*\(|class\s+\w+\s*\([^)]*\bFastMCP\b[^)]*\)\s*:`)
	pythonClientConstructionPattern = regexp.MustCompile(`ClientSession\s*\(`)

	// The namespace clause also covers a server built on the low-level
	// mcp.server.lowlevel.Server API, which never calls FastMCP(...).
	pythonServerPattern = regexp.MustCompile(pythonServerNamespaceImportPattern.String() + `|` + pythonServerConstructionPattern.String())
	pythonClientPattern = regexp.MustCompile(pythonClientNamespaceImportPattern.String() + `|` + pythonClientConstructionPattern.String())

	// .NET: dotnetServerPattern requires a `.` immediately before
	// Add<anything>McpServer( so it matches a call site
	// (builder.Services.AddAzureMcpServer(...)) and not the definition of
	// such a helper, where the return type precedes the name. The wildcard
	// is there because servers commonly wrap the SDK's AddMcpServer() in a
	// helper of their own (AddAzureMcpServer), which is then the only call
	// a server's source makes.
	dotnetServerPattern = regexp.MustCompile(`\.Add\w*McpServer\s*\(|\busing\s+ModelContextProtocol\.Server(?:\.\w+)*\s*;`)
	dotnetClientPattern = regexp.MustCompile(`\.AddMcpClient\s*\(|McpClientFactory\.Create|\busing\s+ModelContextProtocol\.Client(?:\.\w+)*\s*;`)

	// Java: `import io.modelcontextprotocol.server...;` or the builder
	// entry point McpServer.sync|async(...), and the client equivalents.
	javaServerNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.server(?:\.\w+)*\s*;`)
	javaServerConstructionPattern    = regexp.MustCompile(`\bMcpServer\.(?:sync|async)\s*\(`)
	javaClientNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.client(?:\.\w+)*\s*;`)
	javaClientConstructionPattern    = regexp.MustCompile(`\bMcpClient\.(?:sync|async)\s*\(`)
	javaServerPattern                = regexp.MustCompile(javaServerNamespaceImportPattern.String() + `|` + javaServerConstructionPattern.String())
	javaClientPattern                = regexp.MustCompile(javaClientNamespaceImportPattern.String() + `|` + javaClientConstructionPattern.String())

	// Rust: rmcp servers implement the ServerHandler trait (clients,
	// ClientHandler) or have #[tool_router(server_handler)] generate the impl,
	// and import from rmcp's handler::server module (resp. handler::client).
	// The alternatives cover a grouped use (`use rmcp::{..., ServerHandler};`,
	// `use rmcp::{handler::server::wrapper::Parameters, ...};`), a flat
	// qualified path, the impl block itself, bare or path-qualified (`impl
	// mcp::ServerHandler for`, when the crate is renamed in Cargo.toml), and
	// the macro attribute.
	rustServerPattern = regexp.MustCompile(`\brmcp::\{[^}]*\b(?:ServerHandler|handler::server)\b|\brmcp::(?:\w+::)*ServerHandler\b|\brmcp::handler::server\b|\bimpl\s+(?:\w+::)*ServerHandler\s+for\b|#\[tool_router\s*\(\s*server_handler\b`)
	rustClientPattern = regexp.MustCompile(`\brmcp::\{[^}]*\b(?:ClientHandler|handler::client)\b|\brmcp::(?:\w+::)*ClientHandler\b|\brmcp::handler::client\b|\bimpl\s+(?:\w+::)*ClientHandler\s+for\b`)
)

// nodeModuleSpecifier matches module, quoted, as the specifier of an import:
// `from "m"` (import and re-export), `import "m"`, `import("m")` and
// `require("m")`.
func nodeModuleSpecifier(module string) string {
	return `(?:\bfrom|\bimport\s*\(?|\brequire\s*\()\s*["'\x60]` + module + `["'\x60]`
}

// Patterns used only to classify a manifest-less Python script
// (discover_python_script.go): pythonMainGuardPattern and
// pythonRunCallPattern require an executable entrypoint, not just an import,
// before such a script is classified a server.
var (
	pythonMainGuardPattern = regexp.MustCompile(`if\s+__name__\s*==\s*['"]__main__['"]\s*:`)
	pythonRunCallPattern   = regexp.MustCompile(`\.run\s*\(|\.serve\s*\(`)
	// legacyPythonScriptPrefilterPattern is the cheap check discovery runs
	// on every manifest-less .py file to pick candidates; classification
	// (classifyPythonScriptProject) then decides their Role.
	legacyPythonScriptPrefilterPattern = regexp.MustCompile(`\bfastmcp\b|\bmcp\.server\b|\bmcp\.client\b`)
)

// ecosystemSourceExtensions are the source files each ecosystem's
// classifier and hasOwnEntrypointEvidence read.
var ecosystemSourceExtensions = map[string][]string{
	"go":     {".go"},
	"node":   {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
	"python": {".py"},
	"dotnet": {".cs"},
	"java":   {".java"},
	"rust":   {".rs"},
}

// wrapperEntrypointPatterns are per-ecosystem "this program starts a
// server" signals, each pattern of which must match one of a project's own
// (non-test) source files: a program running, serving or connecting a
// server, as opposed to a library that merely builds one, or any method
// that happens to be called Run. hasOwnEntrypointEvidence uses them to
// recognize a thin wrapper entrypoint whose server construction lives in a
// workspace-local dependency, and isLaunchable to tell such a program from
// a library.
//
//   - Go: a main function in package main, and a server run or served by
//     it: the SDK's Server.Run with a context (ctx, cmd.Context(),
//     context.Background()) and a transport, mcp-go's ServeStdio, or
//     net/http's ListenAndServe -- never t.Run or exec.Cmd.Run.
//   - Node: nodeEntrypointPattern.
//   - Python: run or serve called on a server, MCP or app object, or the
//     asyncio/anyio/trio/uvicorn call that starts one -- never
//     subprocess.run or an agent's run.
//   - .NET: running the host or web application -- never Task.Run or a
//     command handler's RunAsync.
//   - Java and Rust: the language's own entrypoint marker (static void
//     main, fn main), because their SDKs have no single startup call to
//     look for.
var wrapperEntrypointPatterns = map[string][]*regexp.Regexp{
	"go": {
		regexp.MustCompile(`(?ms)^package\s+main\b.*^func\s+main\s*\(\s*\)`),
		regexp.MustCompile(`\.Run\s*\(\s*(?:\w*[cC]tx\w*|context\.\w+\(\s*\)|[\w.]*Context\(\s*\))\s*,|\bServeStdio\s*\(|\bListenAndServe(?:TLS)?\s*\(`),
	},
	"node":   {nodeEntrypointPattern},
	"python": {regexp.MustCompile(`(?i)\b\w*(?:mcp|server|app)\.(?:run|serve)\s*\(|\b(?:asyncio|anyio|trio|uvicorn)\.run\s*\(`)},
	"dotnet": {regexp.MustCompile(`(?i:\b\w*(?:app|host))\s*\.\s*Run(?:Async)?\s*\(|\.Build\s*\(\s*\)\s*\.\s*Run(?:Async)?\s*\(`)},
	"java":   {regexp.MustCompile(`\bpublic\s+static\s+void\s+main\s*\(`)},
	"rust":   {regexp.MustCompile(`\bfn\s+main\s*\(`)},
}

// nodeEntrypointPattern is Node's startup call: a server connected to a
// transport, an HTTP server listening on a port, or a serve() call (Hono's
// Node adapter, serveStdio) -- never db.connect() or a mock server's
// listen({ onUnhandledRequest }).
var nodeEntrypointPattern = regexp.MustCompile(`\.connect\s*\(\s*(?:new\s+\w*Transport\b|[\w$.]*[tT]ransport\b)|\.listen\s*\(\s*(?:\d|[^,)]*(?i:port))|\bserveStdio\s*\(|\bserve\s*\(\s*\{`)

// classifyRoles assigns an initial Role to every project, independently of
// the dependency graph (shared-library promotion happens afterward, in
// graph.go, once it's known which projects are actually referenced by a
// server). Each project gets exactly one of: RoleMCPServer, RoleMCPClient,
// RoleConsumerConfigOnly, or RoleUnrelated.
func classifyRoles(projects []*Project) {
	for _, p := range projects {
		role, evidence := classifyProject(p, projects)
		p.Role = role
		p.Evidence = evidence
	}
}

func classifyProject(p *Project, allProjects []*Project) (Role, []string) {
	if isTestShapedProject(p) {
		return classifyTestShapedProject(p, allProjects)
	}
	return classifyByEcosystem(p, allProjects)
}

// classifyByEcosystem classifies p from its ecosystem's SDK profile: a
// project whose manifest declares the MCP SDK is a server or a client by
// what its source constructs; one without it can only be a consumer config
// or unrelated.
func classifyByEcosystem(p *Project, allProjects []*Project) (Role, []string) {
	if p.Ecosystem == "python-script" {
		return classifyPythonScriptProject(p)
	}
	profile, ok := sdkProfiles[p.Ecosystem]
	if !ok {
		return RoleUnrelated, nil
	}
	sdk, hasSDK, err := profile.sdkDependency(p)
	if err != nil {
		return RoleUnrelated, nil
	}
	if !hasSDK {
		return consumerOrUnrelated(p)
	}
	patterns := map[string]*regexp.Regexp{"server": profile.server, "client": profile.client}
	if clientOnlySDKs[sdk] {
		delete(patterns, "server") // nothing to build a server with
	}
	return roleFromSignals(sdk, projectSourceSignals(p, allProjects, ecosystemSourceExtensions[p.Ecosystem], patterns))
}

// clientOnlySDKs are SDK packages that can only build clients.
var clientOnlySDKs = map[string]bool{"@modelcontextprotocol/client": true}

// sdkProfile is how one ecosystem's MCP SDK shows up: the dependency a
// project's manifest declares, and the source patterns of server and client
// code.
type sdkProfile struct {
	// sdkDependency names the MCP SDK p's manifest depends on; ok is false
	// when it depends on none, and err is set when the manifest is
	// unreadable.
	sdkDependency  func(p *Project) (sdk string, ok bool, err error)
	server, client *regexp.Regexp
}

var sdkProfiles = map[string]sdkProfile{
	"go":     {goSDKDependency, goServerPattern, goClientPattern},
	"node":   {nodeSDKDependency, nodeServerPattern, nodeClientPattern},
	"python": {pythonProjectSDKDependency, pythonServerPattern, pythonClientPattern},
	"dotnet": {dotnetSDKDependency, dotnetServerPattern, dotnetClientPattern},
	"java":   {javaSDKDependency, javaServerPattern, javaClientPattern},
	"rust":   {rustSDKDependency, rustServerPattern, rustClientPattern},
}

// testShapedPathSegmentPattern and testShapedNameSuffixPattern together
// decide whether a project is "test-shaped": its directory sits under a
// test/tests/__tests__ path segment, or its own directory basename ends in
// a conventional test suffix (.Tests/.Test/_test/_tests, case-insensitive).
// A test project that constructs a real server for its integration tests
// (Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests) is
// indistinguishable from a server by source signal alone.
var (
	testShapedPathSegmentPattern = regexp.MustCompile(`(?i)(^|[/\\])(tests?|__tests__)([/\\]|$)`)
	testShapedNameSuffixPattern  = regexp.MustCompile(`(?i)([._]tests?)$`)
)

// isTestShapedProject reports whether p's directory looks like a test
// project by naming convention alone, independent of its source content. A
// test-shaped project is never classified RoleMCPServer regardless of what
// SDK construction calls its own source contains (see classifyProject and
// promoteWrapperServers in wrapper_classify.go, which both consult this).
//
// Only the repository-relative location (p.RelDir) is matched: a checkout
// that happens to live under an ancestor named test/tests/__tests__ must not
// make every project inside it look test-shaped (demoting every server and
// leaving nothing selectable). The repository root itself is never
// test-shaped by name -- its directory name is chosen by whoever cloned it,
// not by the project. Without a known RelDir, only the project's own
// directory basename is checked, the one part of an absolute path that is
// always the project's own.
func isTestShapedProject(p *Project) bool {
	if p.RelDir == "" {
		return testShapedNameSuffixPattern.MatchString(filepath.Base(p.Dir))
	}
	return isTestShapedDir(p.RelDir)
}

// isTestShapedDir applies isTestShapedProject's rule to a repository-relative
// directory in POSIX form.
func isTestShapedDir(relDir string) bool {
	return relDir != "." && (testShapedPathSegmentPattern.MatchString(relDir) || testShapedNameSuffixPattern.MatchString(path.Base(relDir)))
}

// classifyTestShapedProject still runs the normal ecosystem classification
// (to get the right Evidence trail and to distinguish a genuine
// RoleMCPClient/RoleConsumerConfigOnly from RoleUnrelated where relevant),
// but downgrades a RoleMCPServer conclusion to RoleMCPClient -- a test
// project that constructs a server to exercise it is, at most, acting as
// that server's own client/harness, never a standalone target of its own.
func classifyTestShapedProject(p *Project, allProjects []*Project) (Role, []string) {
	role, evidence := classifyByEcosystem(p, allProjects)
	if role != RoleMCPServer {
		return role, evidence
	}
	return RoleMCPClient, append(evidence, "directory is test-shaped (path segment or name suffix); a server-construction call here is treated as test harness code, not a standalone server")
}

func goSDKDependency(p *Project) (string, bool, error) {
	mf, err := readGoMod(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	for _, req := range mf.Require {
		if req.Mod.Path == goSDKModulePath || strings.HasPrefix(req.Mod.Path, goSDKModulePath+"/") {
			return goSDKModulePath, true, nil
		}
	}
	return "", false, nil
}

func nodeSDKDependency(p *Project) (string, bool, error) {
	pkg, err := readPackageJSON(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	dependencies := pkg.allDependencies()
	for _, sdk := range nodeSDKPackages {
		if pkg.Name == sdk {
			return "", false, nil // the SDK itself, not a user of it
		}
	}
	for _, sdk := range nodeSDKPackages {
		if _, ok := dependencies[sdk]; ok {
			return sdk, true, nil
		}
	}
	return "", false, nil
}

func pythonProjectSDKDependency(p *Project) (string, bool, error) {
	doc, err := readPyprojectToml(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	sdk, ok := pythonSDKDependency(doc)
	return sdk, ok, nil
}

func dotnetSDKDependency(p *Project) (string, bool, error) {
	doc, err := readCsproj(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	return dotnetSDKPackagePrefix, dotnetPackageReferencePrefix(doc, dotnetSDKPackagePrefix), nil
}

func javaSDKDependency(p *Project) (string, bool, error) {
	doc, err := readPom(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	return javaSDKGroupID, javaGroupIDDependency(doc, javaSDKGroupID), nil
}

// rustSDKDependency also follows dependencies the crate inherits from its
// Cargo workspace.
func rustSDKDependency(p *Project) (string, bool, error) {
	doc, err := readCargoToml(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	var workspace *cargoWorkspace
	if repoRoot, ok := projectRepoRoot(p); ok {
		workspace = findCargoWorkspace(repoRoot, p.Dir, doc, make(map[string]*cargoWorkspace))
	}
	return rustSDKCrateName, cargoHasDependency(doc, rustSDKCrateName, workspace), nil
}

// roleFromSignals turns the construction calls found in source into a Role
// for a project that depends on an MCP SDK. A server signal wins over a
// client one (a server may use a client internally; it still has to be
// scanned as a server). With neither signal the project defaults to client:
// an unrecognized SDK use is left out of the target list rather than made a
// selectable target.
func roleFromSignals(sdkEvidence string, signals map[string]bool) (Role, []string) {
	evidence := []string{"depends on " + sdkEvidence}
	switch {
	case signals["server"]:
		return RoleMCPServer, append(evidence, "source contains a server-construction call")
	case signals["client"]:
		return RoleMCPClient, append(evidence, "source contains a client-construction call")
	default:
		return RoleMCPClient, append(evidence, "no server/client construction call found; defaulting to client")
	}
}

// consumerOrUnrelated handles a project with no MCP SDK dependency of its
// own: it is classified RoleConsumerConfigOnly if it merely configures
// external MCP servers (an mcp.json-shaped file with an "mcpServers" key),
// and RoleUnrelated otherwise: a client configuration file never makes a
// project a server.
func consumerOrUnrelated(p *Project) (Role, []string) {
	if hasConsumerConfig(p) {
		return RoleConsumerConfigOnly, []string{"contains an MCP client configuration file but no MCP SDK dependency"}
	}
	return RoleUnrelated, nil
}

// hasConsumerConfig looks for an MCP client configuration file (mcp.json,
// .cursor/mcp.json, a claude_desktop_config.json-shaped file, ...) under the
// project's directory, confirming it by parsing the file and checking for
// the "mcpServers" key rather than matching on filename alone.
func hasConsumerConfig(p *Project) bool {
	found := false
	_ = walkFiles(p.Dir, nil, func(path string, info os.FileInfo) error {
		name := strings.ToLower(info.Name())
		if name != "mcp.json" && name != "mcp_config.json" && !strings.Contains(name, "claude_desktop_config") {
			return nil
		}
		var doc map[string]interface{}
		if readJSONFile(path, &doc) != nil {
			return nil
		}
		if _, ok := doc["mcpServers"]; ok {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// pythonSDKPackages are the Python MCP SDK distributions, in the order
// pythonSDKDependency prefers them: a project declaring both is reported as
// depending on the official "mcp" package on every run, whatever order its
// TOML tables come in.
var pythonSDKPackages = []string{"mcp", "fastmcp"}

// pythonSDKDependency names the Python MCP SDK the pyproject.toml document
// depends on: among the dependencies the project runs with
// (pythonRuntimeDependencies: PEP 621's [project].dependencies and
// optional-dependencies, Poetry's main table) or a Poetry dependency group.
// An SDK declared only as an extra ("pip install mytool[mcp]") is still
// what the project's server code is written against.
func pythonSDKDependency(doc map[string]interface{}) (string, bool) {
	declared := pythonRuntimeDependencies(doc)
	for _, deps := range poetryDependencyTables(doc) {
		for name := range deps {
			declared[normalizePEP503(name)] = true
		}
	}
	for _, sdk := range pythonSDKPackages {
		if declared[sdk] {
			return sdk, true
		}
	}
	return "", false
}

// pep508PackageName extracts the package name from a PEP 508 dependency
// specifier string, e.g. "fastmcp>=2.0" -> "fastmcp", "mcp[cli]==1.2" -> "mcp".
func pep508PackageName(spec string) string {
	spec = strings.TrimSpace(spec)
	for i, r := range spec {
		switch r {
		case '[', '=', '>', '<', '!', '~', ';', ' ':
			return spec[:i]
		}
	}
	return spec
}

// projectSourceSignals reports which of the named patterns match a file
// under project.Dir whose name ends with one of extensions. It never
// descends into another project nested in that tree (one that
// ownsDirectory), so a nested project's code cannot change this project's
// role, and it skips the project's tests and fixtures (src/test/, tests/,
// foo_test.go, foo.test.ts, ...): a library whose tests start a server is
// not a server.
func projectSourceSignals(project *Project, allProjects []*Project, extensions []string, patterns map[string]*regexp.Regexp) map[string]bool {
	projDir := filepath.Clean(project.Dir)
	nestedProjectDirs := make(map[string]bool)
	for _, other := range allProjects {
		if otherDir := filepath.Clean(other.Dir); otherDir != projDir && within(otherDir, projDir) && ownsDirectory(other) {
			nestedProjectDirs[otherDir] = true
		}
	}
	isNestedProject := func(dir string) bool { return nestedProjectDirs[filepath.Clean(dir)] }

	found := make(map[string]bool, len(patterns))
	_ = walkSourceFiles(project.Dir, isNestedProject, func(path string, info os.FileInfo) error {
		if !hasAnyExt(info.Name(), extensions) || isTestSource(projDir, path) {
			return nil
		}
		content, err := readFileCapped(path)
		if err != nil {
			return nil
		}
		for name, pattern := range patterns {
			if !found[name] && pattern.Match(content) {
				found[name] = true
			}
		}
		if len(found) == len(patterns) {
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// ownsDirectory reports whether p owns the directory it was found in, and
// so bounds the source of a project enclosing it. A manifest-less Python
// script owns only its own file: the files beside it still belong to the
// project around them, as a Node server's src/ holding a Python smoke-test
// client is still the server's source.
func ownsDirectory(p *Project) bool {
	return p.Ecosystem != "python-script"
}

// isTestSource reports whether path is one of the project's tests or
// fixtures, judged by its path below the project directory.
func isTestSource(projDir, path string) bool {
	switch aggregation.ContextForPath(repoRelative(projDir, path)) {
	case "test", "fixture":
		return true
	}
	return false
}

func hasAnyExt(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
