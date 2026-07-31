// Minimal MCP server on the OFFICIAL SDK. Every handler below takes its tool input as a
// TYPED STRUCT parameter -- there is no RequireString/GetString accessor anywhere, which
// is precisely why the mark3labs-scoped source predicate sees nothing here.
//
// Handlers are registered in three shapes to prove the source predicate binds all of them:
// a NAMED function (runPing/readFile), an INLINE func literal (fetch_url), and a closure
// bound to a VARIABLE first (lookup). Before the FuncLit arm in isOfficialSdkHandler, the
// two closure shapes produced zero sources -- the same silent clean zero the review filed,
// just a different registration shape.
package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type PingArgs struct {
	Host string `json:"host"`
}

type ReadArgs struct {
	Path string `json:"path"`
}

type FetchArgs struct {
	URL string `json:"url"`
}

type QueryArgs struct {
	Query string `json:"query"`
}

// SINK 1 (named handler): command injection -- args.Host flows into exec.Command.
func runPing(ctx context.Context, req *mcp.CallToolRequest, args PingArgs) (*mcp.CallToolResult, any, error) {
	out, err := exec.Command("sh", "-c", "ping -c 1 "+args.Host).CombinedOutput()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

// SINK 2 (named handler): path traversal -- args.Path flows into os.ReadFile.
func readFile(ctx context.Context, req *mcp.CallToolRequest, args ReadArgs) (*mcp.CallToolResult, any, error) {
	b, err := os.ReadFile(args.Path)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "0.0.1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "run_ping", Description: "ping a host"}, runPing)
	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: "read a file"}, readFile)

	// SINK 3 (INLINE func literal): ssrf -- args.URL flows into http.Get. No named handler
	// produces ssrf, so an ssrf finding can only come from this literal-registered closure.
	mcp.AddTool(s, &mcp.Tool{Name: "fetch_url"},
		func(ctx context.Context, req *mcp.CallToolRequest, args FetchArgs) (*mcp.CallToolResult, any, error) {
			resp, err := http.Get(args.URL)
			if err != nil {
				return nil, nil, err
			}
			_ = resp.Body.Close()
			return &mcp.CallToolResult{}, nil, nil
		})

	// SINK 4 (closure bound to a VARIABLE, then registered): sqli -- args.Query flows into
	// db.QueryContext. Only this handler produces sqli, so a sqli finding proves the
	// variable-bound closure shape is a source too.
	lookup := func(ctx context.Context, req *mcp.CallToolRequest, args QueryArgs) (*mcp.CallToolResult, any, error) {
		db, err := sql.Open("sqlite", "file:x.db")
		if err != nil {
			return nil, nil, err
		}
		defer db.Close()
		if _, err := db.QueryContext(ctx, "select * from u where id = "+args.Query); err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{}, nil, nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "lookup"}, lookup)

	_ = s.Run(context.Background(), &mcp.StdioTransport{})
}
