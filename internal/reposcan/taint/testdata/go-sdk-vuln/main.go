// Minimal MCP server on the OFFICIAL SDK. Every handler below takes its tool input as a
// TYPED STRUCT parameter -- there is no RequireString/GetString accessor anywhere, which
// is precisely why the mark3labs-scoped source predicate sees nothing here.
package main

import (
	"context"
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

// SINK 1: command injection -- args.Host flows into exec.Command.
func runPing(ctx context.Context, req *mcp.CallToolRequest, args PingArgs) (*mcp.CallToolResult, any, error) {
	out, err := exec.Command("sh", "-c", "ping -c 1 "+args.Host).CombinedOutput()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

// SINK 2: path traversal -- args.Path flows into os.ReadFile.
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
	_ = s.Run(context.Background(), &mcp.StdioTransport{})
}
