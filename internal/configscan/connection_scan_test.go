package configscan

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPrintsNoServerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	cfg := `{"mcpServers":{"local":{"command":"node","args":["server.js"],"env":{"API_KEY":"CANARY-SECRET"}}}}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	_, scanErr := NewConnectionScanner(path).Scan(context.Background())
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if scanErr != nil || strings.Contains(string(out), "CANARY-SECRET") || !strings.Contains(string(out), "Scanning MCP Server local") {
		t.Fatalf("err %v; stdout %q; want the server name without its config", scanErr, out)
	}
}

func TestScanPrintsNoURLSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	cfg := `{"mcpServers":{"remote":{"type":"http","url":"mcp://example.com/CANARY-PATH?api_key=CANARY-QUERY"}}}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	_, scanErr := NewConnectionScanner(path).Scan(context.Background())
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if scanErr == nil || strings.Contains(string(out)+scanErr.Error(), "CANARY") || !strings.Contains(string(out), "Scanning MCP Server remote") {
		t.Fatalf("err %v; stdout %q; want the connection error without the URL path or query", scanErr, out)
	}
}
