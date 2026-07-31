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
