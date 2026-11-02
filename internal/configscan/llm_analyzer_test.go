package configscan

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseBatchLLMResponseEmptyResults(t *testing.T) {
	findings, err := (&LLMAnalyzer{}).parseBatchLLMResponse(`{"results":[]}`, nil, "srv", "mcp.json")
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings %d, err %v; want none and no error", len(findings), err)
	}
}

func TestParseBatchLLMResponseInvalidFindings(t *testing.T) {
	tools := []*mcp.Tool{{Name: "read_record"}}
	for _, response := range []string{
		`{"results":[null]}`, `[null]`,
		`{"results":[{"tool_name":"read_record"},null]}`,
		`[{"tool_name":"read_record"},null]`,
		`{"results":null}`, `{}`,
	} {
		t.Run(response, func(t *testing.T) {
			findings, err := (&LLMAnalyzer{}).parseBatchLLMResponse(response, tools, "srv", "mcp.json")
			if err == nil || len(findings) != 0 {
				t.Fatalf("findings %d, err %v; want an error and no findings", len(findings), err)
			}
		})
	}
}

func TestBatchAnalysisPromptSpecifiesEmptyResults(t *testing.T) {
	prompt := (&LLMAnalyzer{}).buildBatchAnalysisPrompt(nil)
	if !strings.Contains(prompt, `If there are no findings, return {"results": []}.`) {
		t.Fatal("prompt must specify the empty findings response")
	}
}
