package taint

import "testing"

// TestCodeQLTimeoutFromEnv covers the V44-3 override. The per-language budget was a hard
// 600s that nothing could change, so a large target died as an opaque `signal: killed`.
// A malformed or nonsensical value must fall back to the default rather than producing a
// zero/negative budget, which would kill every language instantly.
func TestCodeQLTimeoutFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		want      int
	}{
		{"unset falls back", "", codeqlDefaultTimeoutSec},
		{"explicit override", "1800", 1800},
		{"unparseable falls back", "abc", codeqlDefaultTimeoutSec},
		{"zero falls back", "0", codeqlDefaultTimeoutSec},
		{"negative falls back", "-5", codeqlDefaultTimeoutSec},
		{"whitespace falls back", "   ", codeqlDefaultTimeoutSec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCPXRAY_CODEQL_TIMEOUT", tc.env)
			if got := codeqlTimeoutFromEnv(); got != tc.want {
				t.Errorf("MCPXRAY_CODEQL_TIMEOUT=%q -> %d, want %d", tc.env, got, tc.want)
			}
		})
	}
}

// TestCodeQLConfigForOverride locks the --codeql-timeout precedence that sast.go wires
// through CodeQLConfigFor: an explicit flag (>0) wins over MCPXRAY_CODEQL_TIMEOUT, and a
// zero/negative flag is treated as unset and keeps the env default. Nothing else exercises
// the "flag wins" contract, so deleting the override would otherwise pass every test.
func TestCodeQLConfigForOverride(t *testing.T) {
	t.Setenv("MCPXRAY_CODEQL_TIMEOUT", "700")
	if got := CodeQLConfigFor(1800).TimeoutSec; got != 1800 {
		t.Errorf("flag set: TimeoutSec = %d, want 1800 (flag must win over env 700)", got)
	}
	if got := CodeQLConfigFor(0).TimeoutSec; got != 700 {
		t.Errorf("flag unset: TimeoutSec = %d, want 700 (env default kept)", got)
	}
	if got := CodeQLConfigFor(-5).TimeoutSec; got != 700 {
		t.Errorf("negative flag: TimeoutSec = %d, want 700 (treated as unset)", got)
	}
	t.Setenv("MCPXRAY_CODEQL_TIMEOUT", "")
	if got := CodeQLConfigFor(0).TimeoutSec; got != codeqlDefaultTimeoutSec {
		t.Errorf("flag+env unset: TimeoutSec = %d, want %d", got, codeqlDefaultTimeoutSec)
	}
}

// TestDefaultCodeQLConfigCarriesTimeout locks that the resolved config actually carries the
// budget. TimeoutSec was previously never set to anything but the constant, so a config
// that silently reported 0 would reintroduce the "dies instantly" failure.
func TestDefaultCodeQLConfigCarriesTimeout(t *testing.T) {
	t.Setenv("MCPXRAY_CODEQL_TIMEOUT", "1234")
	if got := DefaultCodeQLConfig().TimeoutSec; got != 1234 {
		t.Errorf("DefaultCodeQLConfig().TimeoutSec = %d, want 1234", got)
	}
	t.Setenv("MCPXRAY_CODEQL_TIMEOUT", "")
	if got := DefaultCodeQLConfig().TimeoutSec; got != codeqlDefaultTimeoutSec {
		t.Errorf("unset -> TimeoutSec = %d, want %d", got, codeqlDefaultTimeoutSec)
	}
}
