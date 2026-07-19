package taint

import "gopkg.in/yaml.v3"

// DefaultClasses are the taint classes generated when the caller passes none.
var DefaultClasses = []string{"command_injection", "path_traversal", "ssrf", "sqli"}

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
}

// baseSinksPy lists dangerous sink patterns per class. Each references $SINK, which
// the rule focuses so the match points at the tainted argument.
var baseSinksPy = map[string][]string{
	"command_injection": {
		"os.system($SINK)", "os.popen($SINK)",
		"subprocess.run($SINK, ..., shell=True, ...)",
		"subprocess.Popen($SINK, ..., shell=True, ...)",
		"subprocess.call($SINK, ..., shell=True, ...)",
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
		"sqlalchemy.text($SINK)", "text($SINK)",
	},
}

type patternGroup struct {
	Patterns []map[string]string `yaml:"patterns"`
}

type ogRule struct {
	ID       string            `yaml:"id"`
	Language []string          `yaml:"languages"`
	Severity string            `yaml:"severity"`
	Mode     string            `yaml:"mode"`
	Message  string            `yaml:"message"`
	Metadata map[string]string `yaml:"metadata"`
	Sources  []patternGroup    `yaml:"pattern-sources"`
	Sinks    []patternGroup    `yaml:"pattern-sinks"`
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
			ID:       "mcpxray-py-" + vc,
			Language: []string{"python"},
			Severity: "ERROR",
			Mode:     "taint",
			Message:  "MCP handler input reaches a " + vc + " sink.",
			Metadata: map[string]string{"vuln_class": vc},
			Sources:  sources,
			Sinks:    sinks,
		})
	}
	return yaml.Marshal(doc)
}
