// Package taint runs a source->sink taint engine (OpenGrep) over an MCP server
// repo and turns proven taint paths into findings. It complements, and never
// replaces, the existing YARA/SCA/secrets scanners.
package taint

import "strconv"

// PathRecord is one proven source->sink taint path. The handler function and tainted
// parameter come from engine metavariables ($F, $SRC), so no AST pass is needed.
type PathRecord struct {
	VulnClass      string
	SourceFile     string
	SourceLine     int
	SourceFunction string // $F: the MCP tool/handler the taint originates in
	SourceParam    string // $SRC: the tainted handler parameter
	SinkFile       string
	SinkLine       int
	SinkAPI        string
	Engine         string
	RuleID         string
	IsCrossFile    bool
	SinkSnippet    string
	Steps          []string
}

// pathID is a stable identity for merge/dedup across engines. It includes the source
// file (not just the sink) so two same-named handlers in different files reaching one
// shared cross-file sink are not falsely deduped; the sink line disambiguates two sinks
// of the same api in one function. SourceLine is included so two distinct flows that share
// a sink but originate on different lines -- common when the handler name is "unknown"
// (setRequestHandler, multi-line registrations), which bypasses the sameFlow gate via this
// exact-match fast path -- are not collapsed into one, dropping a finding. A genuine
// cross-engine duplicate reported at different source lines still merges via sinkIdentity.
func (p PathRecord) pathID() string {
	return p.VulnClass + "|" + p.SourceFile + "|" + p.SinkFile + "|" + p.SourceFunction + "|" +
		p.SinkAPI + "|" + p.SourceParam + "|" + strconv.Itoa(p.SinkLine) + "|" + strconv.Itoa(p.SourceLine)
}

// --- OpenGrep JSON (only the fields we consume) ---

type ogOutput struct {
	Results []ogResult `json:"results"`
	Errors  []ogError  `json:"errors"`
}

type ogError struct {
	Message string `json:"message"`
	Level   string `json:"level"` // "error" = fatal (bad/missing ruleset); others are benign
}

type ogResult struct {
	CheckID string  `json:"check_id"`
	Path    string  `json:"path"`
	Start   ogPos   `json:"start"`
	End     ogPos   `json:"end"`
	Extra   ogExtra `json:"extra"`
}

type ogPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type ogExtra struct {
	Metavars      map[string]ogMetavar `json:"metavars"`
	DataflowTrace ogTrace              `json:"dataflow_trace"`
	Message       string               `json:"message"`
}

type ogMetavar struct {
	AbstractContent string `json:"abstract_content"`
	Start           ogPos  `json:"start"`
}

type ogTrace struct {
	IntermediateVars []ogInterVar `json:"intermediate_vars"`
}

type ogInterVar struct {
	Content  string `json:"content"`
	Location struct {
		Path  string `json:"path"`
		Start ogPos  `json:"start"`
	} `json:"location"`
}
