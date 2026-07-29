package taint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// CodeQL adds cross-file, interprocedural taint via the pinned bundle and the
// version-controlled mcp_taint query packs. Python and JavaScript/TypeScript extract
// build-free (source parsed, target never executed); Go has no build-free mode, so its
// DB build compiles the target and is gated behind explicit consent (see consent.go).

// our lang -> CodeQL language id; the pack lives under codeql/<cqLang>/. TypeScript
// uses the javascript extractor (handles .ts and .js).
var codeqlLangs = map[string]string{"python": "python", "go": "go", "typescript": "javascript"}

var (
	reTaintClass = regexp.MustCompile(`MCP-TAINT\[([a-z_]+)\]`)
	// The message is `... sink=<api>: ...`; capture up to the ": " delimiter so an api that
	// itself contains a colon (e.g. node:http.get) is not truncated at the first colon.
	reSinkAPI = regexp.MustCompile(`sink=(\S+?):\s`)
	// A named handler declaration + its param list: Python `def f(...)`, Go `func f(...)`
	// or method `func (r T) f(...)`, and JS/TS `function f(...)` (incl. export/async).
	reHandler = regexp.MustCompile(`\b(?:func\s+(?:\([^)]*\)\s*)?|def\s+|function\s+)([A-Za-z_$][\w$]*)\s*\(([^)]*)\)`)
	// Same declaration but only up to the open paren, for a signature split across lines.
	reHandlerName = regexp.MustCompile(`\b(?:func\s+(?:\([^)]*\)\s*)?|def\s+|function\s+)([A-Za-z_$][\w$]*)\s*\(`)
	// JS/TS arrow handler assigned to a name: `const f = (args) =>` / `= async (args) =>`.
	reArrowHandler = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>`)
	// Go closure assigned to a name then registered separately (`h := func(ctx, in) {`,
	// `var h = func(ctx, in) {`), the mcp-go `srv.AddTool(tool, h)` shape. Named here so
	// the upward scan stops at the closure instead of walking on to the enclosing `main`.
	// `:?=` matches `:=`/`=` but a struct field `Handler: func(...)` is not (it has `:`
	// without `=`); `x := funcCall()` is not (`func\s*\(` needs `(` right after `func`).
	reGoClosure = regexp.MustCompile(`\b(?:var\s+)?([A-Za-z_$][\w$]*)\s*:?=\s*func\s*\(([^)]*)\)`)
	// JS/TS inline MCP registration `server.tool("name", (args) => {`: an anonymous callback
	// whose tool-NAME string is the attribution, with the param on the same line.
	reInlineHandler = regexp.MustCompile("\\.(?:tool|registerTool|resource)\\s*\\(\\s*[\"'`]([^\"'`]+)[\"'`]\\s*,\\s*(?:async\\s+)?(?:function\\s*)?\\(([^)]*)\\)")
	// A JS/TS class or object-literal method declaration -- `async runCmd(args) {`,
	// `public handle(req): void {`, `run_cmd(args) {`. Anchored and keyword-guarded (see
	// notMethodKeyword) so a control statement like `if (cond) {` is never read as a handler.
	reMethodDecl = regexp.MustCompile(`^\s*(?:(?:public|private|protected|static|readonly|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::[^{;]*)?\{\s*$`)
	// A class body or object-literal opening ABOVE the source: we have left the handler's
	// scope, so stop rather than walking into an unrelated earlier declaration.
	reScopeBoundary = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+[A-Za-z_$]|^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*(?::[^=]*)?=\s*\{\s*$`)
	// Registration calls that ENCLOSE a handler body. Includes the Go SDK / mcp-go
	// AddTool|AddResource|AddPrompt|AddResourceTemplate forms, whose handler is a closure
	// -- without them the upward scan runs past the registration and names the enclosing
	// func (typically `main`) as the MCP tool.
	reRegBoundary = regexp.MustCompile(`\.(?:tool|registerTool|resource|setRequestHandler|AddTool|AddResource|AddPrompt|AddResourceTemplate)\s*\(`)
	reRegName     = regexp.MustCompile("\\.(?:tool|registerTool|resource)\\s*\\(\\s*[\"'`]([^\"'`]+)[\"'`]")
	reIdent       = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)`)
	// A Go anonymous func literal opening a callback body on the registration line
	// (`AddTool(tool, func(ctx, req) {`). Word-boundary anchored so it matches `func(` /
	// `func (` but never a named `func main(` or an identifier ending in "func" (someFunc().
	reFuncLit = regexp.MustCompile(`\bfunc\s*\(`)
)

// CodeQLConfig controls the CodeQL taint engine. Zero value is not usable; call
// DefaultCodeQLConfig.
type CodeQLConfig struct {
	Bin          string // codeql executable
	PackDir      string // dir containing <lang>/mcp_taint.ql
	TimeoutSec   int
	AllowGoBuild bool // consent to compile Go targets (see consent.go)
}

// DefaultCodeQLConfig resolves the pinned bundle and packs. Zero value is not usable.
func DefaultCodeQLConfig() CodeQLConfig {
	return CodeQLConfig{Bin: findCodeQL(), PackDir: findPackDir(), TimeoutSec: 600}
}

// findCodeQL resolves the codeql executable only from an explicit, pinned source:
// MCPXRAY_CODEQL_BIN (an exe or a bundle dir), then bin/codeql-bundle/codeql/codeql next
// to the mcpxray binary. It deliberately does NOT fall back to a `codeql` on PATH, so
// plain repo-scan never auto-activates cross-file analysis from an unrelated/unpinned
// engine; to use one off PATH, set MCPXRAY_CODEQL_BIN to its full path (a bare name is
// not PATH-resolved). "" when none is usable.
func findCodeQL() string {
	if b := os.Getenv("MCPXRAY_CODEQL_BIN"); b != "" {
		// Absolutize against the current CWD (where isExec/Stat validate it) so a relative
		// MCPXRAY_CODEQL_BIN can never later resolve against the scanned repo and run an
		// attacker-planted binary (mirrors findOpengrep).
		if abs, err := filepath.Abs(b); err == nil {
			b = abs
		}
		if fi, err := os.Stat(b); err == nil && fi.IsDir() {
			// Accept either the dir that directly holds the exe or a bundle root, whose
			// standard layout nests it under codeql/ (<bundle>/codeql/<exe>).
			for _, c := range []string{filepath.Join(b, codeqlExe()), filepath.Join(b, "codeql", codeqlExe())} {
				if isExec(c) {
					return c
				}
			}
		} else if isExec(b) {
			return b
		}
	}
	if exe, err := os.Executable(); err == nil {
		if c := filepath.Join(filepath.Dir(exe), "bin", "codeql-bundle", "codeql", codeqlExe()); isExec(c) {
			return c
		}
	}
	return ""
}

// codeqlExe is the bundle's CLI filename for the current OS (codeql.exe on Windows),
// so the bundle-dir and next-to-binary lookups resolve on every platform.
func codeqlExe() string {
	if runtime.GOOS == "windows" {
		return "codeql.exe"
	}
	return "codeql"
}

// findPackDir resolves the query packs from MCPXRAY_CODEQL_PACKS or next to the mcpxray
// binary. Returns "" (not a CWD-relative guess) when neither resolves, so Available() is
// honestly false rather than self-activating from a ./codeql in the working directory.
func findPackDir() string {
	if d := os.Getenv("MCPXRAY_CODEQL_PACKS"); d != "" {
		// Absolutize against the current CWD (where Available()'s Stat validates it) so a
		// relative MCPXRAY_CODEQL_PACKS can't later resolve against the scanned repo and load
		// attacker-planted query packs (mirrors findCodeQL / findOpengrep).
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
		return d
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "codeql")
	}
	return ""
}

// CodeQLEngine runs the CodeQL taint packs over a repo. Construct with NewCodeQLEngine.
type CodeQLEngine struct{ cfg CodeQLConfig }

// NewCodeQLEngine returns an engine bound to cfg.
func NewCodeQLEngine(cfg CodeQLConfig) *CodeQLEngine { return &CodeQLEngine{cfg: cfg} }

// Available reports whether the codeql binary and at least one query pack were resolved.
func (e *CodeQLEngine) Available() bool {
	if e.cfg.Bin == "" || e.cfg.PackDir == "" {
		return false
	}
	if fi, err := os.Stat(e.cfg.PackDir); err != nil || !fi.IsDir() {
		return false
	}
	// Require an actual pack. A directory that merely EXISTS would otherwise report
	// available, and Scan would then skip every language (each fileExists(ql) misses) and
	// return no paths and no error -- making a misconfigured MCPXRAY_CODEQL_PACKS
	// indistinguishable from a clean deep scan.
	for _, cqLang := range codeqlLangs {
		if fileExists(filepath.Join(e.cfg.PackDir, cqLang, "mcp_taint.ql")) {
			return true
		}
	}
	return false
}

// Scan runs CodeQL for each supported language present in langs and returns the merged
// paths plus a joined error for any language whose analysis FAILED. Languages that
// succeed still contribute their paths; the error lets the caller distinguish "ran clean"
// from "engine broke" so a failed analysis is never silently reported as zero findings.
func (e *CodeQLEngine) Scan(ctx context.Context, repoPath string, langs []string) ([]PathRecord, error) {
	if !e.Available() {
		return nil, nil
	}
	// Backstop: never exec a relative engine path (findCodeQL already absolutizes). A
	// relative bin could resolve against the scanned repo and run an attacker binary.
	if !filepath.IsAbs(e.cfg.Bin) {
		return nil, fmt.Errorf("codeql binary path must be absolute, got %q", e.cfg.Bin)
	}
	// Same backstop for the pack dir (joined into the query path below): findPackDir
	// absolutizes, but a hand-built CodeQLConfig with a relative PackDir would otherwise
	// load query packs from the scanned repo's CWD.
	if !filepath.IsAbs(e.cfg.PackDir) {
		return nil, fmt.Errorf("codeql pack dir must be absolute, got %q", e.cfg.PackDir)
	}
	root, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}
	var out []PathRecord
	var errs []error
	for _, lang := range langs {
		cqLang, ok := codeqlLangs[lang]
		if !ok {
			continue
		}
		if lang == "go" && !e.cfg.AllowGoBuild {
			continue // Go DB build compiles the target; skipped without consent.
		}
		ql := filepath.Join(e.cfg.PackDir, cqLang, "mcp_taint.ql")
		if !fileExists(ql) {
			continue
		}
		sarif, err := e.runLang(ctx, root, cqLang, ql)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", lang, err))
			continue
		}
		out = append(out, e.parseSarif(sarif, root)...)
	}
	return out, errors.Join(errs...)
}

// codeqlKillGrace is how long a codeql subprocess may run after its context is cancelled
// before it is force-killed, so a hung run cannot outlive the deadline and block the
// CombinedOutput read on its pipes.
const codeqlKillGrace = 10 * time.Second

// runLang builds a CodeQL DB and analyzes it. Failures return an error (with the
// engine's own output) so a broken run is never silently reported as no findings.
func (e *CodeQLEngine) runLang(ctx context.Context, root, cqLang, ql string) (*cqSarif, error) {
	db, err := os.MkdirTemp("", "mcpxray-cqdb-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(db)
	dbPath := filepath.Join(db, "db")
	sarifPath := filepath.Join(db, "out.sarif")

	timeout := e.cfg.TimeoutSec // default a partial Config so ctx isn't instantly expired
	if timeout <= 0 {
		timeout = 600
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	createArgs := []string{"database", "create", dbPath, "--language=" + cqLang,
		"--source-root=" + root, "--overwrite", "--quiet"}
	if cqLang != "go" {
		// Enforce build-free extraction for python/javascript by flag rather than relying
		// on the default, so nothing in the target is executed. Go is the only build path,
		// and it is gated by explicit consent (see consent.go).
		createArgs = append(createArgs, "--build-mode=none")
	}
	create := exec.CommandContext(ctx, e.cfg.Bin, createArgs...)
	create.WaitDelay = codeqlKillGrace
	if o, err := create.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("database create: %w: %s", err, tail(o))
	}
	analyze := exec.CommandContext(ctx, e.cfg.Bin, "database", "analyze", dbPath, ql,
		"--format=sarif-latest", "--output="+sarifPath,
		"--search-path="+searchPath(e.cfg.Bin), "--rerun", "--quiet", "--threads=0")
	analyze.WaitDelay = codeqlKillGrace
	if o, err := analyze.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("database analyze: %w: %s", err, tail(o))
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("read sarif: %w", err)
	}
	var s cqSarif
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	return &s, nil
}

// tail returns the last chunk of engine output for an error message.
func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return "..." + s[len(s)-200:]
	}
	return s
}

func (e *CodeQLEngine) parseSarif(s *cqSarif, root string) []PathRecord {
	var out []PathRecord
	// Cache each source file's lines so many results in one file don't re-read it.
	fileLines := map[string][]string{}
	for _, run := range s.Runs {
		for _, r := range run.Results {
			// CodeQL escapes [ ] in SARIF message text (brackets denote embedded links);
			// unescape just those, not every backslash, so Windows paths and other escapes
			// in the message aren't corrupted (which could break sink= parsing).
			msg := strings.NewReplacer(`\[`, "[", `\]`, "]").Replace(r.Message.Text)
			m := reTaintClass.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			vc := m[1]
			nodes := threadNodes(r)
			if len(nodes) == 0 {
				continue
			}
			srcURI := normURI(nodes[0].uri)
			sinkURI := normURI(nodes[len(nodes)-1].uri)
			srcLine, sinkLine := nodes[0].line, nodes[len(nodes)-1].line
			srcAbs := resolveInRoot(root, srcURI)
			sinkAbs := resolveInRoot(root, sinkURI)
			if !withinRoot(sinkAbs, root) || !withinRoot(srcAbs, root) {
				continue
			}
			sinkSnippet := snippet(fileLines, sinkAbs, sinkLine, sinkLine)
			sinkAPI := "unknown_sink"
			if a := reSinkAPI.FindStringSubmatch(msg); a != nil {
				sinkAPI = a[1]
			} else if sinkSnippet != "" {
				// The python pack emits no sink= tag and its sink node is the tainted
				// ARGUMENT, so a call wrapped across lines leaves the api name on the line
				// ABOVE (the call opens there) and the one-line snippet yields unknown_sink
				// -- which also poisons pathID/sinkIdentity and defeats the cross-engine
				// merge. Retry once over the sink line plus the line above. Never widen
				// BELOW: the next line can be an unrelated statement whose api would be
				// stolen (a path_traversal open() sink mislabelled with the following
				// os.system) -- an honest unknown_sink beats a confidently wrong label.
				sinkAPI = canonicalSinkAPI(sinkSnippet)
				if sinkAPI == "unknown_sink" {
					if wide := snippet(fileLines, sinkAbs, sinkLine-1, sinkLine); wide != "" {
						if a := canonicalSinkAPI(wide); a != "unknown_sink" {
							sinkAPI = a
						}
					}
				}
			}
			fn, param := enclosingHandler(srcAbs, srcLine)
			out = append(out, PathRecord{
				VulnClass:      vc,
				SourceFile:     relToRoot(srcAbs, root),
				SourceLine:     srcLine,
				SourceFunction: fn,
				SourceParam:    param,
				SinkFile:       relToRoot(sinkAbs, root),
				SinkLine:       sinkLine,
				SinkAPI:        sinkAPI,
				Engine:         "codeql",
				RuleID:         "mcp/taint",
				IsCrossFile:    srcAbs != sinkAbs, // resolved paths: robust to file:// vs relative URIs
				SinkSnippet:    sinkSnippet,
			})
		}
	}
	return out
}

// notMethodKeyword are control-flow keywords that reMethodDecl would otherwise capture
// as a method name (`if (cond) {`, `catch (e) {`, ...).
var notMethodKeyword = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true,
	"do": true, "else": true, "try": true, "return": true, "with": true,
	"function": true, "class": true,
	// `func` guards a Go anonymous closure `func(ctx, in) {`: reMethodDecl runs before the
	// registration-boundary check and would otherwise attribute the sink to a tool literally
	// named "func" instead of stopping at the enclosing AddTool.
	"func": true,
}

// enclosingHandler scans upward from line for the nearest def/func declaration and
// returns its name and first parameter. Best-effort (no AST): the SARIF region gives
// only the source line, not the column, so on a multi-param handler this names the
// first param, not necessarily the tainted one. Cross-engine merge therefore keys on
// the sink identity (see MergePaths), not this param name.
func enclosingHandler(file string, line int) (name, param string) {
	data, err := os.ReadFile(file)
	if err != nil || line <= 0 {
		return "unknown", "unknown"
	}
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		line = len(lines)
	}
	for i := line - 1; i >= 0; i-- {
		ln := lines[i]
		// Strongest signals first: a full named declaration, then an inline registration
		// whose tool-name string and callback param are both on this line. Inline is tried
		// before the boundary so the callback is named for its tool, not left "unknown".
		if m := reHandler.FindStringSubmatch(ln); m != nil {
			return m[1], firstParam(m[2])
		}
		if m := reInlineHandler.FindStringSubmatch(ln); m != nil {
			return m[1], firstParam(m[2])
		}
		// A Go closure assigned to a name (`h := func(ctx, in) {`) -- named for the var so
		// the scan stops here instead of reaching the enclosing `main`. Tried before the
		// arrow check; neither pattern's regex matches the other.
		if m := reGoClosure.FindStringSubmatch(ln); m != nil {
			return m[1], firstParam(m[2])
		}
		// A named arrow handler is tried before the boundary so one whose body itself
		// calls a registration API (`const f = (a) => svc.resource(a)`) is named for the
		// arrow rather than mistaken for a boundary.
		if m := reArrowHandler.FindStringSubmatch(ln); m != nil {
			return m[1], firstParam(m[2])
		}
		// A class/object-literal method (`async runCmd(args) {`) -- the standard TS MCP
		// handler shape, which carries no func/def/function keyword.
		if m := reMethodDecl.FindStringSubmatch(ln); m != nil && !notMethodKeyword[m[1]] {
			return m[1], firstParam(m[2])
		}
		// A registration call that ENCLOSES the source is the source's own boundary: stop
		// so the scan never runs past it into a PRIOR tool (the false-accusation bug).
		// Forms the inline regex can't parse (3-arg registerTool, multi-line,
		// setRequestHandler) yield the tool name when present on this line, else "unknown".
		if reRegBoundary.MatchString(ln) && enclosesSource(ln) {
			if m := reRegName.FindStringSubmatch(ln); m != nil {
				return m[1], "unknown"
			}
			return "unknown", "unknown"
		}
		// Leaving the enclosing class/object scope: report "unknown" rather than blaming
		// whatever declaration happens to sit above it.
		if reScopeBoundary.MatchString(ln) {
			return "unknown", "unknown"
		}
		// A declaration whose signature is split across lines (`def f(` / `func f(`).
		if m := reHandlerName.FindStringSubmatch(ln); m != nil {
			return m[1], "unknown"
		}
	}
	return "unknown", "unknown"
}

// enclosesSource reports whether a matched MCP registration line plausibly encloses the
// source below it rather than being a self-contained call within a handler body. A
// boundary either carries its callback on the line (`=>` or `function`) or is left open
// for the callback to continue below (ends with `(` or `,`); a call that closes on its
// own line (`audit.tool("x");`) is an ordinary body call, not a boundary.
func enclosesSource(ln string) bool {
	if strings.Contains(ln, "=>") || strings.Contains(ln, "function") {
		return true
	}
	t := strings.TrimSpace(ln)
	t = strings.TrimSpace(strings.TrimRight(t, ";"))
	// A Go anonymous func literal (mcp-go `AddTool(tool, func(ctx, req) {`). Go uses `func`,
	// not `function`, and its one-line form ends in `{`, so without this the scan runs past
	// the registration and misreports the enclosing func (`main`). Require the trailing `{`
	// so a self-contained body call whose literal closes on the same line
	// (`f("k", func(y){ return y })`) is NOT mistaken for a boundary.
	if reFuncLit.MatchString(ln) && strings.HasSuffix(t, "{") {
		return true
	}
	return strings.HasSuffix(t, "(") || strings.HasSuffix(t, ",")
}

// firstParam returns the identifier of the first parameter in a signature's param
// list, stripping any type annotation (`host: str` -> host, `url string` -> url).
func firstParam(params string) string {
	for _, raw := range strings.Split(params, ",") {
		p := strings.TrimSpace(strings.SplitN(raw, ":", 2)[0]) // python `name: T`
		m := reIdent.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		// Skip receivers and the injected Go context param: neither is ever the attacker-
		// controlled value, so reporting them as the tainted parameter is always wrong.
		// The context param is skipped by TYPE, not name, so the idiomatic `_ context.Context`
		// / `c context.Context` / unnamed forms are all handled; a Python param literally
		// named ctx carries no such type and is still returned.
		switch {
		case m[1] == "self" || m[1] == "cls":
			continue
		case strings.Contains(raw, "context.Context"):
			continue
		}
		return m[1] // handles go `name T` and bare `name`
	}
	return "unknown"
}

func searchPath(bin string) string {
	// The bundle dir (parent of the codeql binary) ships the <lang>-all library packs, so
	// it resolves query dependencies offline. Resolve symlinks first: a system install
	// often links codeql into e.g. /usr/local/bin, whose dir has no qlpacks -- we need the
	// real bundle dir the link points at.
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real
	}
	return filepath.Dir(bin)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// normURI turns a SARIF artifactLocation.uri into a plain path: strips a file:
// scheme and percent-decodes it (CodeQL encodes spaces and other characters).
func normURI(uri string) string {
	if strings.HasPrefix(uri, "file:") {
		if u, err := url.Parse(uri); err == nil && u.Path != "" {
			// url.Parse already percent-decodes the path; decode once. A Windows URI
			// yields "/C:/repo/x.py" -- drop the leading slash so the drive letter leads
			// and filepath.IsAbs recognises it (otherwise resolveInRoot would join the
			// whole absolute path under the scan root).
			p := u.Path
			if len(p) > 2 && p[0] == '/' && p[2] == ':' {
				p = p[1:]
			}
			return p
		}
	}
	if dec, err := url.PathUnescape(uri); err == nil {
		return dec
	}
	return uri
}

// resolveInRoot joins a relative SARIF uri to the scan root; an absolute uri is used
// as-is (withinRoot still confines it before any read).
func resolveInRoot(root, uri string) string {
	// filepath.IsAbs is GOOS-specific (false for "/etc/passwd" on Windows), so also treat a
	// leading / or \ as absolute -- mirroring parse.go. Without this a POSIX-shaped absolute
	// path would be joined under root on Windows, producing a bogus path that still passes
	// the withinRoot confinement check.
	if filepath.IsAbs(uri) || strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, `\`) {
		return uri
	}
	return filepath.Join(root, uri)
}

type nodeLoc struct {
	uri  string
	line int
}

func threadNodes(r cqResult) []nodeLoc {
	var out []nodeLoc
	if len(r.CodeFlows) > 0 && len(r.CodeFlows[0].ThreadFlows) > 0 {
		for _, tl := range r.CodeFlows[0].ThreadFlows[0].Locations {
			pl := tl.Location.PhysicalLocation
			if pl.ArtifactLocation.URI != "" && pl.Region.StartLine > 0 {
				out = append(out, nodeLoc{pl.ArtifactLocation.URI, pl.Region.StartLine})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if len(r.Locations) > 0 {
		pl := r.Locations[0].PhysicalLocation
		if pl.ArtifactLocation.URI != "" && pl.Region.StartLine > 0 {
			out = append(out, nodeLoc{pl.ArtifactLocation.URI, pl.Region.StartLine})
		}
	}
	return out
}

// --- CodeQL SARIF (only the fields we consume) ---

type cqSarif struct {
	Runs []cqRun `json:"runs"`
}

type cqRun struct {
	Results []cqResult `json:"results"`
}

type cqResult struct {
	Message   cqText       `json:"message"`
	Locations []cqLoc      `json:"locations"`
	CodeFlows []cqCodeFlow `json:"codeFlows"`
}

type cqText struct {
	Text string `json:"text"`
}

type cqLoc struct {
	PhysicalLocation cqPhysical `json:"physicalLocation"`
}

type cqPhysical struct {
	ArtifactLocation cqArtifact `json:"artifactLocation"`
	Region           cqRegion   `json:"region"`
}

type cqArtifact struct {
	URI string `json:"uri"`
}

type cqRegion struct {
	StartLine int `json:"startLine"`
}

type cqCodeFlow struct {
	ThreadFlows []cqThreadFlow `json:"threadFlows"`
}

type cqThreadFlow struct {
	Locations []cqThreadLoc `json:"locations"`
}

type cqThreadLoc struct {
	Location cqLoc `json:"location"`
}
