package targetresolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mcpxray/internal/reposcan"
)

const (
	goSDKModulePath        = "github.com/modelcontextprotocol/go-sdk"
	nodeSDKPackage         = "@modelcontextprotocol/sdk"
	dotnetSDKPackagePrefix = "ModelContextProtocol"
	javaSDKGroupID         = "io.modelcontextprotocol.sdk"
	rustSDKCrateName       = "rmcp"
)

var (
	// Patterns are qualified with the SDK's own canonical identifier
	// (mcp.NewServer, not a bare NewServer) to keep the false-positive rate
	// down; they are only ever checked against projects whose manifest
	// already declares the matching SDK dependency, which narrows things
	// further. Import aliasing (`import s "github.com/.../mcp"`) would evade
	// this -- a known, accepted limitation of a heuristic, regex-based
	// signal, consistent with how the rest of this codebase's SAST/token
	// analyzers already work (internal/yararules, internal/configscan/tokenanalyzer).
	//
	// Go is deliberately left as call-syntax-only: its SDK does not split
	// NewServer/NewClient into separate importable namespaces the way
	// Node/Python/.NET do below, and no real repo examined so far shows a
	// Go server missed by this pattern.
	goServerPattern = regexp.MustCompile(`mcp\.NewServer\(`)
	goClientPattern = regexp.MustCompile(`mcp\.NewClient\(`)

	// nodeServerPattern/nodeClientPattern OR the original construction-call
	// signal with a namespace-import signal: any quoted import/require
	// specifier naming the SDK's server (resp. client) sub-path, regardless
	// of how the imported symbol is then used (a bare `new McpServer()`, a
	// `class Foo extends McpServer`, a dynamic import, a re-export). This is
	// what's needed for real repos like microsoft/rushstack's
	// @rushstack/mcp-server, whose server.ts does
	// `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"`
	// then `class RushMCPServer extends McpServer {` -- a subclass, never a
	// bare `new McpServer(...)` call, which the call-only signal alone
	// misses. The construction-call clause is kept (not replaced) so every
	// existing fixture keeps matching unchanged.
	nodeServerPattern = regexp.MustCompile(`new\s+(McpServer|Server)\s*\(|["']@modelcontextprotocol/sdk/server(?:/[^"']*)?["']`)
	nodeClientPattern = regexp.MustCompile(`new\s+Client\s*\(|["']@modelcontextprotocol/sdk/client(?:/[^"']*)?["']`)

	// Python: fine-grained sub-signals, reused independently by
	// classifyPythonScriptProject (discover_python_script.go) for the
	// manifest-less legacy-script case, and combined here into
	// pythonServerPattern/pythonClientPattern for the normal pyproject.toml
	// path.
	//
	// pythonServerNamespaceImportPattern deliberately does NOT match a bare
	// `from fastmcp import ...` / `import fastmcp` -- the standalone fastmcp
	// package exports both FastMCP (server) and Client (client) from its top
	// level, so a bare-module import can't disambiguate direction; matching
	// it here would falsely tag `from fastmcp import Client` as server
	// evidence. It's scoped to the official mcp package's mcp.server/
	// mcp.client subpackages, which genuinely are directionally split.
	pythonServerNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.server(?:\.\w+)*\s+import\b|\bimport\s+mcp\.server(?:\.\w+)*\b`)
	pythonClientNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.client(?:\.\w+)*\s+import\b|\bimport\s+mcp\.client(?:\.\w+)*\b`)
	// pythonServerConstructionPattern matches a bare FastMCP(...) call OR a
	// class subclassing FastMCP (class Foo(FastMCP): ...) -- confirmed
	// necessary by awslabs/mcp's real s3-tables-mcp-server, which subclasses
	// FastMCP and never calls it directly.
	pythonServerConstructionPattern = regexp.MustCompile(`FastMCP\s*\(|class\s+\w+\s*\([^)]*\bFastMCP\b[^)]*\)\s*:`)
	pythonClientConstructionPattern = regexp.MustCompile(`ClientSession\s*\(`)

	// pythonServerPattern/pythonClientPattern additionally cover
	// awslabs/mcp's healthlake-mcp-server, which constructs the low-level
	// `mcp.server.lowlevel.Server` API directly -- matched by the namespace
	// import clause, since it never calls FastMCP(...) at all.
	pythonServerPattern = regexp.MustCompile(pythonServerNamespaceImportPattern.String() + `|` + pythonServerConstructionPattern.String())
	pythonClientPattern = regexp.MustCompile(pythonClientNamespaceImportPattern.String() + `|` + pythonClientConstructionPattern.String())

	// dotnetServerPattern requires a `.` immediately before Add<anything>McpServer(
	// to match a call site (services.AddMcpServer(...), builder.Services.AddAzureMcpServer(...))
	// and not a method *definition* (public static IServiceCollection
	// AddAzureMcpServer(this IServiceCollection services, ...) -- no `.`
	// immediately precedes the name there, since it's preceded by the return
	// type). The <anything> wildcard is deliberate: real-world .NET MCP
	// repos wrap the official SDK's own AddMcpServer() in a repo-specific
	// helper (confirmed by reading microsoft/mcp's actual source -- every
	// server there calls AddAzureMcpServer(, not AddMcpServer( directly; the
	// real SDK call only appears inside that wrapper's own definition). A
	// pattern hardcoded to either name alone would miss real servers or
	// require per-vendor special-casing; this matches both structurally.
	//
	// The `using ModelContextProtocol.Server`/`.Client` alternative is added
	// for cross-ecosystem consistency with the Node/Python namespace signals
	// above -- no confirmed .NET miss exists today (Tier 1's server.json
	// detection already finds every real .NET server seen so far), this is
	// purely additive and proactive.
	dotnetServerPattern = regexp.MustCompile(`\.Add\w*McpServer\s*\(|\busing\s+ModelContextProtocol\.Server(?:\.\w+)*\s*;`)
	dotnetClientPattern = regexp.MustCompile(`\.AddMcpClient\s*\(|McpClientFactory\.Create|\busing\s+ModelContextProtocol\.Client(?:\.\w+)*\s*;`)

	// Java: namespace-import signal (matches the same "match the SDK's
	// package, not one construction idiom" principle as Node/Python/.NET
	// above) OR'd with a construction-call signal. Both confirmed directly
	// against oracle/mcp's real oracle-db-mcp-toolkit:
	// `import io.modelcontextprotocol.server.McpServer;` plus
	// `McpServer.sync(new StdioServerTransportProvider(...))....build()`.
	// The client-side pattern (io.modelcontextprotocol.client /
	// McpClient.sync|async) is added by symmetry with the server-side
	// builder API -- proactive, not directly evidenced by any repo examined
	// this session (no real Java MCP client source was found to confirm
	// against).
	javaServerNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.server(?:\.\w+)*\s*;`)
	javaServerConstructionPattern    = regexp.MustCompile(`\bMcpServer\.(?:sync|async)\s*\(`)
	javaClientNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.client(?:\.\w+)*\s*;`)
	javaClientConstructionPattern    = regexp.MustCompile(`\bMcpClient\.(?:sync|async)\s*\(`)
	javaServerPattern                = regexp.MustCompile(javaServerNamespaceImportPattern.String() + `|` + javaServerConstructionPattern.String())
	javaClientPattern                = regexp.MustCompile(javaClientNamespaceImportPattern.String() + `|` + javaClientConstructionPattern.String())

	// Rust: rmcp's confirmed real usage (BrowserOS's browseros-mcp crate)
	// is a GROUPED use statement --
	// `use rmcp::{..., handler::server::ServerHandler, ...};` -- plus
	// `impl ServerHandler for BrowserMcpService`. Three alternatives cover,
	// respectively: the grouped-brace use form (`rmcp::{...ServerHandler...}`,
	// the exact real shape), a flat qualified path
	// (`rmcp::handler::server::ServerHandler`, for a non-grouped `use`), and
	// the bare trait name in an impl block, so it doesn't depend on exactly
	// how deep or how the `use` path was written. The client-side pattern
	// (ClientHandler) is added by symmetry with rmcp's server/client
	// handler-trait design -- like Java's client pattern above, this is
	// proactive, not directly evidenced (only the server-side trait was
	// observed in the one real Rust MCP crate examined this session).
	rustServerPattern = regexp.MustCompile(`\brmcp::\{[^}]*\bServerHandler\b|\brmcp::(?:\w+::)*ServerHandler\b|\bimpl\s+ServerHandler\s+for\b`)
	rustClientPattern = regexp.MustCompile(`\brmcp::\{[^}]*\bClientHandler\b|\brmcp::(?:\w+::)*ClientHandler\b|\bimpl\s+ClientHandler\s+for\b`)
)

// Patterns used only by discover_python_script.go's classification of a
// manifest-less legacy Python script (structural evidence-combination, not
// a real AST parser -- consistent with every other signal in this file):
// pythonMainGuardPattern and pythonRunCallPattern require an actual
// executable entrypoint, not just an import, before a manifest-less script
// is ever classified a server.
var (
	pythonMainGuardPattern = regexp.MustCompile(`if\s+__name__\s*==\s*['"]__main__['"]\s*:`)
	pythonRunCallPattern   = regexp.MustCompile(`\.run\s*\(|\.serve\s*\(`)
	// legacyPythonScriptPrefilterPattern is a cheap first pass over every
	// manifest-less .py file found during the repo walk, before the more
	// expensive full-evidence check in classifyPythonScriptProject --
	// keeps discovery itself (which finds candidates) separate from
	// classification (which decides Role), the same separation this
	// package already uses everywhere else.
	legacyPythonScriptPrefilterPattern = regexp.MustCompile(`\bfastmcp\b|\bmcp\.server\b|\bmcp\.client\b`)
)

// ecosystemSourceExtensions is the source-file-extension list each
// ecosystem's classifyXProject function scans, factored out once so
// wrapper_classify.go's hasOwnEntrypointEvidence can reuse the same lists
// without duplicating them.
var ecosystemSourceExtensions = map[string][]string{
	"go":     {".go"},
	"node":   {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
	"python": {".py"},
	"dotnet": {".cs"},
	"java":   {".java"},
	"rust":   {".rs"},
}

// wrapperEntrypointPatterns are structural "this file starts something up"
// signals per ecosystem -- a constructed object's *result* being run or
// served, as opposed to merely being imported/instantiated. Used by
// wrapper_classify.go's hasOwnEntrypointEvidence, combined with bin-field
// evidence and dependency-closure SDK evidence, to recognize a thin wrapper
// entrypoint (one whose own file never touches the SDK's server types
// directly; the real construction call lives in a workspace-local
// dependency) as RoleMCPServer. Only Node (twilio-labs/mcp's @twilio-alpha/mcp,
// which wraps @twilio-alpha/openapi-mcp-server) has concrete evidence today;
// Go/Python/.NET support here is proactive, generalizing the same
// mechanism -- and matches a limitation already named and deferred for
// .NET in an earlier pass over microsoft/mcp (a leaf Program.cs that only
// calls a wrapper, never importing the SDK's server namespace directly).
// Java's and Rust's entries deliberately use each language's own universal
// executable-entrypoint marker (a public static void main method; a fn main
// definition) rather than trying to guess an SDK-specific startup-call
// idiom the way the other four ecosystems do -- neither language's real
// evidence examined this session showed a clean, narrow call-site pattern
// analogous to Node's `.connect(`/`.listen(`, and the entrypoint marker
// itself is a more reliable, ecosystem-native signal for "this file starts
// something up" than guessing at SDK method names would be.
var wrapperEntrypointPatterns = map[string]*regexp.Regexp{
	"go":     regexp.MustCompile(`\.Run\s*\(`),
	"node":   regexp.MustCompile(`\.connect\s*\(|\.listen\s*\(`),
	"python": regexp.MustCompile(`\.run\s*\(|\.serve\s*\(`),
	"dotnet": regexp.MustCompile(`\.Run\s*\(\)|\.RunAsync\s*\(`),
	"java":   regexp.MustCompile(`\bpublic\s+static\s+void\s+main\s*\(`),
	"rust":   regexp.MustCompile(`\bfn\s+main\s*\(`),
}

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

func classifyByEcosystem(p *Project, allProjects []*Project) (Role, []string) {
	switch p.Ecosystem {
	case "go":
		return classifyGoProject(p, allProjects)
	case "node":
		return classifyNodeProject(p, allProjects)
	case "python":
		return classifyPythonProject(p, allProjects)
	case "dotnet":
		return classifyDotnetProject(p, allProjects)
	case "java":
		return classifyJavaProject(p, allProjects)
	case "rust":
		return classifyRustProject(p, allProjects)
	case "python-script":
		return classifyPythonScriptProject(p)
	default:
		return RoleUnrelated, nil
	}
}

// testShapedPathSegmentPattern and testShapedNameSuffixPattern together
// decide whether a project is "test-shaped": its directory sits under a
// test/tests/__tests__ path segment, or its own directory basename ends in
// a conventional test suffix (.Tests/.Test/_test/_tests, case-insensitive).
// Reproduces a real phantom-target bug found in microsoft/mcp:
// Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests legitimately
// constructs a real server in its integration tests, which is
// indistinguishable from a genuine server by source signal alone.
var (
	testShapedPathSegmentPattern = regexp.MustCompile(`(?i)(^|[/\\])(tests?|__tests__)([/\\]|$)`)
	testShapedNameSuffixPattern  = regexp.MustCompile(`(?i)([._]tests?)$`)
)

// isTestShapedProject reports whether p's directory looks like a test
// project by naming convention alone, independent of its source content. A
// test-shaped project is never classified RoleMCPServer regardless of what
// SDK construction calls its own source contains (see classifyProject and
// promoteWrapperServers in wrapper_classify.go, which both consult this).
func isTestShapedProject(p *Project) bool {
	dir := filepath.ToSlash(p.Dir)
	if testShapedPathSegmentPattern.MatchString(dir) {
		return true
	}
	return testShapedNameSuffixPattern.MatchString(filepath.Base(dir))
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

func classifyGoProject(p *Project, allProjects []*Project) (Role, []string) {
	mf, err := readGoMod(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	hasSDK := false
	for _, req := range mf.Require {
		if req.Mod.Path == goSDKModulePath || strings.HasPrefix(req.Mod.Path, goSDKModulePath+"/") {
			hasSDK = true
			break
		}
	}
	if !hasSDK {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["go"], map[string]*regexp.Regexp{
		"server": goServerPattern,
		"client": goClientPattern,
	})
	return roleFromSignals(goSDKModulePath, signals)
}

func classifyNodeProject(p *Project, allProjects []*Project) (Role, []string) {
	pkg, err := readPackageJSON(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	_, hasSDK := pkg.allDependencies()[nodeSDKPackage]
	if !hasSDK {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["node"], map[string]*regexp.Regexp{
		"server": nodeServerPattern,
		"client": nodeClientPattern,
	})
	return roleFromSignals(nodeSDKPackage, signals)
}

func classifyDotnetProject(p *Project, allProjects []*Project) (Role, []string) {
	doc, err := readCsproj(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	if !dotnetPackageReferencePrefix(doc, dotnetSDKPackagePrefix) {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["dotnet"], map[string]*regexp.Regexp{
		"server": dotnetServerPattern,
		"client": dotnetClientPattern,
	})
	return roleFromSignals(dotnetSDKPackagePrefix, signals)
}

func classifyPythonProject(p *Project, allProjects []*Project) (Role, []string) {
	doc, err := readPyprojectToml(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	sdkName, hasSDK := pythonSDKDependency(doc)
	if !hasSDK {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["python"], map[string]*regexp.Regexp{
		"server": pythonServerPattern,
		"client": pythonClientPattern,
	})
	return roleFromSignals(sdkName, signals)
}

func classifyJavaProject(p *Project, allProjects []*Project) (Role, []string) {
	doc, err := readPom(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	if !javaGroupIDDependency(doc, javaSDKGroupID) {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["java"], map[string]*regexp.Regexp{
		"server": javaServerPattern,
		"client": javaClientPattern,
	})
	return roleFromSignals(javaSDKGroupID, signals)
}

func classifyRustProject(p *Project, allProjects []*Project) (Role, []string) {
	doc, err := readCargoToml(p.ManifestPath)
	if err != nil {
		return RoleUnrelated, nil
	}

	if !cargoHasDependency(doc, rustSDKCrateName) {
		return consumerOrUnrelated(p)
	}

	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions["rust"], map[string]*regexp.Regexp{
		"server": rustServerPattern,
		"client": rustClientPattern,
	})
	return roleFromSignals(rustSDKCrateName, signals)
}

// roleFromSignals turns "which construction calls were found in source" into
// a single Role, for a project already confirmed to depend on an MCP SDK.
// Server signal wins over client signal when both are present (a project can
// plausibly both host a server and use a client internally; what matters for
// target-resolution is that it is a server that needs to be scanned as one).
// An SDK dependency with neither signal found defaults to client -- the
// safer default, since classifying an unrecognized SDK usage as a server
// would make it a selectable scan target, while classifying it as a client
// just excludes it from the target list, consistent with this feature's
// opt-in, conservative posture.
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
// and RoleUnrelated otherwise. This is the direct fix for the "MCP consumer
// false positive" pattern: an MCP client configuration file, or a dependency
// on the SDK alone, must never by itself imply this project IS a server.
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
	prune := &reposcan.Config{Root: p.Dir, ExcludedPaths: reposcan.DefaultConfig().ExcludedPaths}
	found := false

	_ = filepath.Walk(p.Dir, func(path string, info os.FileInfo, err error) error {
		if found {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if prune.ShouldExclude(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}

		name := strings.ToLower(info.Name())
		if name != "mcp.json" && name != "mcp_config.json" && !strings.Contains(name, "claude_desktop_config") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		if _, ok := doc["mcpServers"]; ok {
			found = true
		}
		return nil
	})

	return found
}

// pythonSDKDependency reports whether the pyproject.toml document depends on
// the official "mcp" package or "fastmcp", checking both Poetry-style
// dependency tables (exact key match) and PEP 621's [project].dependencies
// array of PEP 508 specifier strings.
func pythonSDKDependency(doc map[string]interface{}) (string, bool) {
	sdkNames := map[string]bool{"mcp": true, "fastmcp": true}

	for _, deps := range poetryDependencyTables(doc) {
		for name := range deps {
			if sdkNames[strings.ToLower(name)] {
				return name, true
			}
		}
	}

	if depsVal, ok := valueAt(doc, "project", "dependencies"); ok {
		if arr, ok := depsVal.([]interface{}); ok {
			for _, item := range arr {
				spec, ok := item.(string)
				if !ok {
					continue
				}
				name := pep508PackageName(spec)
				if sdkNames[strings.ToLower(name)] {
					return name, true
				}
			}
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

// projectSourceSignals walks project.Dir once, reusing reposcan's default
// exclude list to skip dependency caches, and stops descending into any
// other discovered project's own directory so one project's role signal is
// never contaminated by a different project nested inside its directory
// tree. It reports which of the named patterns matched the contents of any
// file whose name ends with one of the given extensions.
func projectSourceSignals(project *Project, allProjects []*Project, extensions []string, patterns map[string]*regexp.Regexp) map[string]bool {
	found := make(map[string]bool, len(patterns))

	projDir := filepath.Clean(project.Dir)
	nestedBoundaries := make(map[string]bool)
	for _, other := range allProjects {
		if other == project {
			continue
		}
		otherDir := filepath.Clean(other.Dir)
		if otherDir != projDir && strings.HasPrefix(otherDir, projDir+string(filepath.Separator)) {
			nestedBoundaries[otherDir] = true
		}
	}

	prune := &reposcan.Config{Root: project.Dir, ExcludedPaths: reposcan.DefaultConfig().ExcludedPaths}

	_ = filepath.Walk(project.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		cleaned := filepath.Clean(path)
		if info.IsDir() {
			if cleaned != projDir && nestedBoundaries[cleaned] {
				return filepath.SkipDir
			}
			if prune.ShouldExclude(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if prune.ShouldExclude(path) || len(found) == len(patterns) {
			return nil
		}
		if !hasAnyExt(info.Name(), extensions) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for name, pattern := range patterns {
			if !found[name] && pattern.Match(content) {
				found[name] = true
			}
		}
		return nil
	})

	return found
}

func hasAnyExt(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
