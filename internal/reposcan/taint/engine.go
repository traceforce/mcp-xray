package taint

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config controls the OpenGrep taint engine. Zero value is not usable; call
// DefaultConfig.
type Config struct {
	OpengrepBin       string
	TimeoutSec        int
	PerRuleTimeoutSec int
	MaxTargetBytes    int
	Classes           []string
	// Excludes are path patterns to skip (forwarded to the engine as --exclude), so
	// taint honors the same exclusions as the SCA/secrets/YARA scans.
	Excludes []string
}

func DefaultConfig() Config {
	return Config{
		OpengrepBin:       findOpengrep(),
		TimeoutSec:        300,
		PerRuleTimeoutSec: 30,
		MaxTargetBytes:    2_000_000,
		// Copy so a caller mutating cfg.Classes can't corrupt the package-global default.
		Classes: append([]string(nil), DefaultClasses...),
	}
}

type Engine struct{ cfg Config }

func NewEngine(cfg Config) *Engine { return &Engine{cfg: cfg} }

// Available reports whether the engine binary was resolved.
func (e *Engine) Available() bool { return e.cfg.OpengrepBin != "" }

// Scan generates taint rules, runs OpenGrep over repoPath, and returns proven paths.
// Returns (nil, nil) when the engine is unavailable so the caller degrades quietly.
func (e *Engine) Scan(ctx context.Context, repoPath string) ([]PathRecord, error) {
	if !e.Available() {
		return nil, nil
	}
	root, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, err
	}
	// Hand OpenGrep the symlink-resolved root. On macOS a repo under /tmp (a symlink to
	// /private/tmp) otherwise makes the engine emit CWD-relative paths -- or exit 0 with
	// zero results -- so taint silently scans nothing. resultsToPaths confines to this
	// same resolved root, so source/sink paths stay consistent.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	rules, err := generatePythonRules(e.cfg.Classes)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "mcpxray-taint-*.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(rules); err != nil {
		tmp.Close()
		return nil, err
	}
	// Check Close: a failed flush would hand OpenGrep an incomplete ruleset.
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	out, err := runOpenGrep(ctx, e.cfg, tmp.Name(), root)
	if err != nil {
		return nil, err
	}
	return resultsToPaths(out, root), nil
}

// MergePaths dedups paths across engines and records every engine that found a path.
// An exact repeat (same pathID) just adds the engine. Beyond that, the same vuln is
// identified by its sink (file, line, api) and enclosing handler -- NOT the source
// parameter name, which engines attribute differently (OpenGrep names the real tainted
// param; CodeQL's best-effort names the handler's first param) -- so a cross-engine
// duplicate merges into one record instead of double-reporting. Two records from the
// SAME engine keep their distinct source params, so single-engine output is unchanged.
func MergePaths(paths []PathRecord) []PathRecord {
	exact := map[string]int{}
	sink := map[string][]int{}
	var out []PathRecord
	for _, p := range paths {
		if idx, ok := exact[p.pathID()]; ok {
			addEngine(&out[idx], p.Engine) // identical path from another engine run
			continue
		}
		// Same vuln located by a different engine: merge into the first record of this
		// sink identity that this engine has not contributed to yet AND that describes the
		// same flow. Tracking every index (not just the first) so multiple params reaching
		// one sink each pair up correctly; the sameFlow gate stops an engine that found a
		// DIFFERENT handler's flow into the same sink from being absorbed and lost.
		merged := false
		for _, idx := range sink[p.sinkIdentity()] {
			if !hasEngine(out[idx].Engine, p.Engine) && sameFlow(out[idx], p) {
				addEngine(&out[idx], p.Engine)
				exact[p.pathID()] = idx // record so a duplicate of this exact path dedups here too
				merged = true
				break
			}
		}
		if merged {
			continue
		}
		exact[p.pathID()] = len(out)
		sink[p.sinkIdentity()] = append(sink[p.sinkIdentity()], len(out))
		out = append(out, p)
	}
	return out
}

// sameFlow reports whether two records with an identical sinkIdentity describe the SAME
// flow, so the cross-engine merge never absorbs (and thereby deletes) a distinct vuln that
// merely shares a sink. Several handlers funnelling into one shared helper is exactly the
// shape CodeQL was added to find, and engine coverage over them is routinely asymmetric.
//
// SourceFunction is the discriminator: it is left out of sinkIdentity because the engines
// DERIVE it differently, but when both recover a concrete name they agree (OpenGrep binds
// the $F metavariable to the def, CodeQL scans up to the same def). SourceParam is
// deliberately not used -- that is the field that genuinely diverges.
//
// A record whose handler an engine could NOT recover ("unknown") deliberately does not
// merge. Letting it match anything would reopen the deletion hole from the other side: an
// unknown-handler record would absorb a concrete, distinct finding and then carry a
// wrongly-corroborated engine tag. Refusing costs at most a duplicate entry, and this file
// prefers a duplicate to a miss (see sinkIdentity). It also keeps the output independent
// of the order the engines' records arrive in, which for CodeQL is raw SARIF order.
func sameFlow(a, b PathRecord) bool {
	if a.SourceFunction == "unknown" || b.SourceFunction == "unknown" {
		return false
	}
	return a.SourceFunction == b.SourceFunction
}

func addEngine(rec *PathRecord, engine string) {
	if rec.Engine == "" {
		rec.Engine = engine
		return
	}
	if !hasEngine(rec.Engine, engine) {
		rec.Engine += "+" + engine
	}
}

// hasEngine reports whether the "+"-joined engine list already contains engine, matching
// whole tokens so one engine name can't substring-match another.
func hasEngine(list, engine string) bool {
	for _, e := range strings.Split(list, "+") {
		if e == engine {
			return true
		}
	}
	return false
}

// sinkIdentity is the cross-engine identity of a vuln: where it lands (sink file, line,
// api) plus the class and source file. It omits the two fields the engines attribute
// differently for the SAME flow -- the source PARAM (OpenGrep names the real tainted
// param, CodeQL the handler's first) and the source FUNCTION (OpenGrep binds the $F
// metavariable, CodeQL recovers the name by scanning upward) -- so those divergences no
// longer split one vuln into two reports.
//
// The sink line and api are deliberately KEPT even though they can also diverge (for
// `p = Path(x); p.read_text()` OpenGrep reports read_text on the second line while CodeQL
// reports the Path() construction on the first, so that case can still double-report).
// Widening the key further would let two genuinely distinct vulns in one file collapse
// into one record, and for a security scanner a duplicate finding is a cosmetic flaw
// whereas a dropped finding is a miss.
func (p PathRecord) sinkIdentity() string {
	return p.VulnClass + "|" + p.SourceFile + "|" + p.SinkFile + "|" +
		strconv.Itoa(p.SinkLine) + "|" + p.SinkAPI
}
