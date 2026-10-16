package targetresolve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// hasOwnEntrypointEvidence reports whether p has independent proof of being
// a launchable entrypoint in its own right, as opposed to being reachable
// merely as a downstream dependency of something else: a declared
// entrypoint (hasDeclaredEntrypoint) or a source-level startup signal
// (every one of its ecosystem's wrapperEntrypointPatterns, signals.go) found
// in its own source.
func hasOwnEntrypointEvidence(p *Project, allProjects []*Project) bool {
	if hasDeclaredEntrypoint(p) {
		return true
	}
	patterns := make(map[string]*regexp.Regexp)
	for i, pattern := range wrapperEntrypointPatterns[p.Ecosystem] {
		patterns[strconv.Itoa(i)] = pattern
	}
	if len(patterns) == 0 {
		return false
	}
	return len(projectSourceSignals(p, allProjects, ecosystemSourceExtensions[p.Ecosystem], patterns)) == len(patterns)
}

// runtimeClosure returns the projects p reaches through the workspace-local
// dependencies it needs to run, leaving out the development-only ones
// recorded in DevLocalDeps (Python dependency groups): a project that pulls
// in a server only to test against it does not wrap it. Node
// devDependencies are followed, since a bundled CLI ships them.
func runtimeClosure(p *Project, dirs projectDirs) []*Project {
	visited := map[*Project]bool{p: true}
	order := []*Project{p}
	for i := 0; i < len(order); i++ {
		current := order[i]
		for _, dir := range current.LocalDeps {
			if slices.Contains(current.DevLocalDeps, dir) {
				continue
			}
			if dep := dirs.dep(current, dir); dep != nil && !visited[dep] {
				visited[dep] = true
				order = append(order, dep)
			}
		}
	}
	return order
}

// hasDeclaredEntrypoint reports whether p's own manifests name something to
// run: a package.json "bin" entry or a Worker's entry module.
func hasDeclaredEntrypoint(p *Project) bool {
	return len(p.BinNames) > 0 || hasWorkerEntrypoint(p)
}

// isLaunchable reports whether p is a program in its own right, which keeps
// it a server even when another server depends on it: it declares an
// entrypoint, or its own source starts something up. For Node the startup
// call must be in a file one of its package.json scripts runs: a connect()
// or listen() call in a library's helper does not make the library a
// program.
func isLaunchable(p *Project, allProjects []*Project) bool {
	if hasDeclaredEntrypoint(p) {
		return true
	}
	if p.Ecosystem == "node" {
		return nodeScriptStartsServer(p, allProjects)
	}
	return hasOwnEntrypointEvidence(p, allProjects)
}

// nodeRunners are the programs that run a JavaScript or TypeScript file, as
// opposed to building, testing or linting it.
var nodeRunners = map[string]bool{"node": true, "tsx": true, "ts-node": true, "ts-node-esm": true, "bun": true, "deno": true, "nodemon": true}

// nodeScriptCommandSeparators split a package.json script into commands.
var nodeScriptCommandSeparators = regexp.MustCompile(`&&|\|\||[;|]`)

// nodeScriptFilePattern matches a JavaScript or TypeScript source file.
var nodeScriptFilePattern = regexp.MustCompile(`^[\w./-]+\.(?:[cm]?[jt]s|[jt]sx)$`)

// scriptRunFiles returns the source files a package.json script runs: the
// files named by each of its commands whose program is a runner, past
// environment assignments and package-manager prefixes ("cross-env A=1 npx
// tsx server.ts" runs server.ts; "esbuild src/index.ts" runs nothing).
func scriptRunFiles(script string) []string {
	var files []string
	for _, command := range nodeScriptCommandSeparators.Split(script, -1) {
		fields := strings.Fields(command)
		for len(fields) > 0 && (strings.Contains(fields[0], "=") || nodePackageRunners[fields[0]]) {
			fields = fields[1:]
		}
		if len(fields) == 0 || !nodeRunners[path.Base(fields[0])] {
			continue
		}
		for _, field := range fields[1:] {
			if nodeScriptFilePattern.MatchString(field) {
				files = append(files, field)
			}
		}
	}
	return files
}

// nodePackageRunners are the prefixes that hand a script's command to the
// program after them.
var nodePackageRunners = map[string]bool{"npx": true, "bunx": true, "pnpm": true, "yarn": true, "exec": true, "dlx": true, "cross-env": true}

// nodeScriptStartsServer reports whether a package.json script of p runs one
// of p's own files that both starts something and holds server code: the
// file a server is launched from, not a client's, a build entry's or a
// nested project's.
func nodeScriptStartsServer(p *Project, allProjects []*Project) bool {
	manifest, err := readPackageJSON(p.ManifestPath)
	if err != nil {
		return false
	}
	for _, raw := range manifest.Scripts {
		var script string
		if json.Unmarshal(raw, &script) != nil {
			continue // npm's "//" comments are not commands
		}
		for _, file := range scriptRunFiles(script) {
			path := filepath.Join(p.Dir, filepath.FromSlash(file))
			if !within(path, p.Dir) || isTestSource(p.Dir, path) || insideNestedProject(path, p.ScanRoot(), nestedProjectRoots(allProjects)) {
				continue
			}
			source, err := readFileCapped(path)
			if err == nil && nodeEntrypointPattern.Match(source) && nodeServerPattern.Match(source) {
				return true
			}
		}
	}
	return false
}

// nestedProjectRoots returns the scan roots of the projects that bound the
// source of a project enclosing them (ownsDirectory).
func nestedProjectRoots(projects []*Project) []string {
	roots := make([]string, 0, len(projects))
	for _, project := range projects {
		if ownsDirectory(project) {
			roots = append(roots, project.ScanRoot())
		}
	}
	return roots
}

// hasWorkerEntrypoint reports whether p is a Cloudflare Worker: its Wrangler
// configuration names, at top level or for an environment, the entry module
// the platform runs, the way a bin entry names a command.
func hasWorkerEntrypoint(p *Project) bool {
	for _, name := range []string{"wrangler.toml", "wrangler.json", "wrangler.jsonc"} {
		path := filepath.Join(p.Dir, name)
		var config map[string]interface{}
		var err error
		if strings.HasSuffix(name, ".toml") {
			err = readTOMLFile(path, &config)
		} else {
			var data []byte
			if data, err = readFileCapped(path); err == nil {
				err = json.Unmarshal(jsoncToJSON(data), &config)
			}
		}
		if err == nil && declaresWorkerMain(config) {
			return true
		}
	}
	return false
}

func declaresWorkerMain(config map[string]interface{}) bool {
	if main, _ := config["main"].(string); main != "" {
		return true
	}
	environments, _ := config["env"].(map[string]interface{})
	for _, value := range environments {
		environment, _ := value.(map[string]interface{})
		if main, _ := environment["main"].(string); main != "" {
			return true
		}
	}
	return false
}

// jsoncToJSON removes the byte order mark, comments and trailing commas
// JSONC allows, leaving string contents untouched.
func jsoncToJSON(data []byte) []byte {
	data = bytes.TrimPrefix(data, utf8BOM)
	var uncommented []byte
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '"':
			end := endOfJSONString(data, i)
			uncommented = append(uncommented, data[i:end]...)
			i = end - 1
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '/':
			for i+1 < len(data) && data[i+1] != '\n' {
				i++
			}
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '*':
			if end := bytes.Index(data[i+2:], []byte("*/")); end >= 0 {
				i += end + 3
			} else {
				i = len(data) // an unterminated comment runs to the end
			}
		default:
			uncommented = append(uncommented, data[i])
		}
	}
	var out []byte
	for i := 0; i < len(uncommented); i++ {
		switch c := uncommented[i]; c {
		case '"':
			end := endOfJSONString(uncommented, i)
			out = append(out, uncommented[i:end]...)
			i = end - 1
		case ',':
			next := bytes.TrimLeft(uncommented[i+1:], " \t\r\n")
			if len(next) > 0 && (next[0] == '}' || next[0] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// endOfJSONString returns the index just past the JSON string starting at
// data[start].
func endOfJSONString(data []byte, start int) int {
	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(data)
}

// hasOwnClientCode reports whether p, a project that depends on an MCP SDK,
// constructs a client in its own source: a test client or a host that
// launches the server it depends on is that server's client, not a wrapper
// around it.
func hasOwnClientCode(p *Project, allProjects []*Project) bool {
	profile, ok := sdkProfiles[p.Ecosystem]
	if !ok {
		return false
	}
	return projectSourceSignals(p, allProjects, ecosystemSourceExtensions[p.Ecosystem], map[string]*regexp.Regexp{"client": profile.client})["client"]
}

// promoteWrapperServers classifies a project RoleMCPServer when it has its
// own entrypoint evidence (hasOwnEntrypointEvidence) AND the workspace-local
// dependencies it needs to run (runtimeClosure) reach a project already
// classified RoleMCPServer -- i.e. the real SDK server-construction call
// lives in a dependency, not in this project's own source (a "wrapper" or
// "composed" server).
//
// For example, @twilio-alpha/mcp has a "bin" entry and a
// `.connect(transport)` call, but the `new Server(...)` call lives in the
// sibling @twilio-alpha/openapi-mcp-server it depends on.
//
// Test-shaped projects (isTestShapedProject) are never promoted: a test
// harness that reaches a real server is not a standalone target. Neither
// is an MCP client with client code of its own (hasOwnClientCode), unless
// it is a deployed Worker: a hosted server may use a client internally, as
// roleFromSignals lets a server signal win for the same reason.
//
// Runs to a fixed point (bounded by len(projects) iterations) so a
// multi-hop wrapper chain (a wrapper of a wrapper) is fully resolved, not
// just one hop.
func promoteWrapperServers(projects []*Project) {
	dirs := indexProjectDirs(projects)

	for iterations := 0; iterations < len(projects); iterations++ {
		changed := false
		for _, p := range projects {
			if p.Role == RoleMCPServer {
				continue
			}
			if p.Ecosystem == "" || p.Ecosystem == "unknown" {
				continue
			}
			if isTestShapedProject(p) {
				continue
			}
			if !hasOwnEntrypointEvidence(p, projects) {
				continue
			}
			if p.Role == RoleMCPClient && !hasWorkerEntrypoint(p) && hasOwnClientCode(p, projects) {
				continue
			}
			for _, dep := range runtimeClosure(p, dirs) {
				if dep != p && dep.Role == RoleMCPServer {
					p.Role = RoleMCPServer
					p.Evidence = append(p.Evidence, fmt.Sprintf(
						"classified as a wrapper/composed MCP server: has its own entrypoint (bin entry, Worker entry module or startup call), and its workspace-local dependency closure reaches the confirmed MCP server %s",
						dep.Name,
					))
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}
}
