package configscan

import "testing"

func TestParseBatchLLMResponseEmptyResults(t *testing.T) {
	findings, err := (&LLMAnalyzer{}).parseBatchLLMResponse(`{"results":[]}`, nil, "srv", "mcp.json")
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings %d, err %v; want none and no error", len(findings), err)
	}
}
