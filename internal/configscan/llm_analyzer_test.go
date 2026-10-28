package configscan

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseBatchLLMResponseShapes(t *testing.T) {
	a := &LLMAnalyzer{}
	tools := []*mcp.Tool{{Name: "exec"}}
	finding := `{"tool_name":"exec","severity":"high","rule_id":"r","title":"t","message":"m"}`
	for _, tc := range []struct {
		name, in string
		want     int
		wantErr  bool
	}{
		{"empty results", `{"results":[]}`, 0, false},
		{"wrapped", `{"results":[` + finding + `]}`, 1, false},
		{"null element", `[null,` + finding + `]`, 1, false},
		{"null", `null`, 0, true},
		{"prose", `none`, 0, true},
	} {
		got, err := a.parseBatchLLMResponse(tc.in, tools, "srv", "cfg")
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if len(got) != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.name, len(got), tc.want)
		}
	}
}
