package taint

import (
	"context"
	"os"
	"path/filepath"
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
		Classes:           DefaultClasses,
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
