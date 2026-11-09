package llm

import (
	"context"
	"strings"
	"testing"
)

// captureChat records the system prompt it was given.
type captureChat struct{ system string }

func (c *captureChat) Chat(_ context.Context, systemPrompt string, _ []ChatMessage) (string, error) {
	c.system = systemPrompt
	return "[]", nil
}

func TestCallLLMSystemPromptIsFormatOnly(t *testing.T) {
	for _, tc := range []struct {
		format int
		want   string
	}{{OutputFormatJSON, "JSON"}, {OutputFormatYAML, "YAML"}} {
		chat := &captureChat{}
		c := &LLMClient{ChatClient: chat}
		if _, err := c.CallLLM(context.Background(), "prompt", tc.format); err != nil {
			t.Fatal(err)
		}
		if s := chat.system; !strings.Contains(s, tc.want) || strings.Contains(s, "finding") || strings.Contains(s, "severity") || strings.Contains(s, "rule_id") {
			t.Errorf("format %d: system prompt must name %s and carry no findings schema: %q", tc.format, tc.want, s)
		}
	}
}
