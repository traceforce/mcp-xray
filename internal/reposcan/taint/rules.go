package taint

import "gopkg.in/yaml.v3"

// DefaultClasses are the taint classes generated when the caller passes none.
var DefaultClasses = []string{"command_injection", "code_injection", "path_traversal", "ssrf", "sqli"}

// baseSourcesPy scopes taint to an MCP handler parameter. Both the decorator-call
// (@mcp.tool()) and bare-attribute (@mcp.tool) registration styles are covered so
// the engine binds $F (handler) and $SRC (param) for either.
var baseSourcesPy = []string{
	"@$SRV.tool(...)\ndef $F(..., $SRC, ...):\n  ...",
	"@$SRV.tool(...)\nasync def $F(..., $SRC, ...):\n  ...",
	"@$SRV.tool\ndef $F(..., $SRC, ...):\n  ...",
	"@$SRV.tool\nasync def $F(..., $SRC, ...):\n  ...",
	"@register_tool(...)\ndef $F(..., $SRC, ...):\n  ...",
	"@register_tool(...)\nasync def $F(..., $SRC, ...):\n  ...",
	"@$SRV.resource(...)\ndef $F(..., $SRC, ...):\n  ...",
	"@$SRV.resource(...)\nasync def $F(..., $SRC, ...):\n  ...",
	// The LOW-LEVEL mcp.server.Server API: a single @server.call_tool() dispatcher
	//   @server.call_tool()
	//   async def call_tool(name: str, arguments: dict): ...
	// where the tainted value is read out as arguments["path"]. This is how the OFFICIAL
	// reference servers (fetch, git, time) are written, and the decorator-name is
	// call_tool -- NOT tool -- so the patterns above never matched it. Without these,
	// every server built on the low-level API is invisible to the engine.
	"@$SRV.call_tool(...)\ndef $F(..., $SRC, ...):\n  ...",
	"@$SRV.call_tool(...)\nasync def $F(..., $SRC, ...):\n  ...",
	"@$SRV.call_tool\ndef $F(..., $SRC, ...):\n  ...",
	"@$SRV.call_tool\nasync def $F(..., $SRC, ...):\n  ...",
}

// baseSanitizersPy kills taint once it has been narrowed to a value the caller cannot
// choose. Kept to COERCIONS only: int/float/bool/uuid each produce a fresh value that no
// traversal/injection payload can survive.
//
// A membership-guarded lookup sanitizer (`if $K in $D: ... $D[$K]`) was tried and
// deliberately REMOVED. The guard only proves the KEY exists; it does not prove the
// container is server-owned. So it also fired on the low-level @server.call_tool() source
// -- `if "path" in arguments: open(arguments["path"])` -- and silently dropped a real
// vulnerability (arguments is itself the tainted object). For a scanner a false negative
// is worse than the handful of hardcoded-registry false positives it removed.
var baseSanitizersPy = []string{
	// Coercions that destroy any traversal/injection payload.
	"int($SINK)", "float($SINK)", "bool($SINK)",
	"uuid.UUID($SINK)",
}

// baseSinksPy lists dangerous sink patterns per class. Each references $SINK, which
// the rule focuses so the match points at the tainted argument.
var baseSinksPy = map[string][]string{
	"command_injection": {
		"os.system($SINK)", "os.popen($SINK)",
		"subprocess.run($SINK, ..., shell=True, ...)",
		"subprocess.Popen($SINK, ..., shell=True, ...)",
		"subprocess.call($SINK, ..., shell=True, ...)",
		"subprocess.check_output($SINK, ..., shell=True, ...)",
		"subprocess.check_call($SINK, ..., shell=True, ...)",
		// getoutput/getstatusoutput are ALWAYS shell -- there is no shell=False form,
		// so no guard is needed (and adding one would never match).
		"subprocess.getoutput($SINK)", "subprocess.getstatusoutput($SINK)",
		// asyncio's shell spawner. Every async MCP server built on FastMCP reaches the
		// shell through this, not through subprocess.*, so omitting it left the single
		// most common async command-injection sink uncovered. Both the qualified and
		// the `from asyncio import ...` bare form; the name is unique enough to be safe
		// unqualified. create_subprocess_EXEC is deliberately NOT here -- it is argv-form
		// and carries no shell, matching the existing shell=True-only stance.
		"asyncio.create_subprocess_shell($SINK, ...)",
		"create_subprocess_shell($SINK, ...)",
		// pty.spawn runs its argument as a program with a controlling terminal.
		"pty.spawn($SINK)",
	},
	// eval/exec run attacker input as code, a distinct class from shell command
	// injection (test_categories.csv INJECTION-CODE vs INJECTION-COMMAND).
	"code_injection": {
		"eval($SINK)", "exec($SINK)",
	},
	"path_traversal": {
		"open($SINK, ...)", "open($SINK)", "io.open($SINK, ...)",
		"os.open($SINK, ...)", "codecs.open($SINK, ...)",
		"Path($SINK).read_text(...)", "Path($SINK).write_text(...)",
		// Receiver form ($P = Path(user); $P.read_text()) -- the common two-statement
		// pattern the inline Path(...).read_text() misses.
		"$SINK.read_text(...)", "$SINK.write_text(...)",
	},
	"ssrf": {
		"requests.get($SINK, ...)", "requests.post($SINK, ...)",
		"requests.request(..., $SINK, ...)", "httpx.get($SINK, ...)",
		"httpx.post($SINK, ...)", "urllib.request.urlopen($SINK, ...)",
		// Any HTTP client's .request(url=...) -- catches client/session.request the
		// requests.*/httpx.* literals miss.
		"$C.request(..., url=$SINK, ...)",
	},
	"sqli": {
		"$CUR.execute($SINK)", "$CUR.execute($SINK, ...)",
		// Only the qualified sqlalchemy.text form; a bare text($SINK) matches any local
		// function named text and false-positives on benign helpers.
		"sqlalchemy.text($SINK)",
	},
}

type patternGroup struct {
	Patterns []map[string]string `yaml:"patterns"`
}

type ogRule struct {
	ID         string            `yaml:"id"`
	Language   []string          `yaml:"languages"`
	Severity   string            `yaml:"severity"`
	Mode       string            `yaml:"mode"`
	Message    string            `yaml:"message"`
	Metadata   map[string]string `yaml:"metadata"`
	Sources    []patternGroup    `yaml:"pattern-sources"`
	Sanitizers []patternGroup    `yaml:"pattern-sanitizers,omitempty"`
	Sinks      []patternGroup    `yaml:"pattern-sinks"`
}

type ogRuleDoc struct {
	Rules []ogRule `yaml:"rules"`
}

// generatePythonRules builds one taint rule per requested class over a shared set of
// handler sources. Built as typed structs and marshalled, so a pattern can never
// break out of the YAML structure.
func generatePythonRules(classes []string) ([]byte, error) {
	if len(classes) == 0 {
		classes = DefaultClasses
	}
	sources := make([]patternGroup, 0, len(baseSourcesPy))
	for _, pi := range baseSourcesPy {
		sources = append(sources, patternGroup{Patterns: []map[string]string{
			{"pattern-inside": pi}, {"focus-metavariable": "$SRC"},
		}})
	}

	sanitizers := make([]patternGroup, 0, len(baseSanitizersPy))
	for _, s := range baseSanitizersPy {
		sanitizers = append(sanitizers, patternGroup{Patterns: []map[string]string{{"pattern": s}}})
	}

	doc := ogRuleDoc{}
	for _, vc := range classes {
		sinkPatterns, ok := baseSinksPy[vc]
		if !ok {
			continue
		}
		sinks := make([]patternGroup, 0, len(sinkPatterns))
		for _, p := range sinkPatterns {
			sinks = append(sinks, patternGroup{Patterns: []map[string]string{
				{"pattern": p}, {"focus-metavariable": "$SINK"},
			}})
		}
		doc.Rules = append(doc.Rules, ogRule{
			ID:         "mcpxray-py-" + vc,
			Language:   []string{"python"},
			Severity:   "ERROR",
			Mode:       "taint",
			Message:    "MCP handler input reaches a " + vc + " sink.",
			Metadata:   map[string]string{"vuln_class": vc},
			Sources:    sources,
			Sanitizers: sanitizers,
			Sinks:      sinks,
		})
	}
	return yaml.Marshal(doc)
}
