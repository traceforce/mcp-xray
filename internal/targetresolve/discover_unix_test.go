//go:build unix

package targetresolve

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO blocks whoever opens it for reading until a writer appears, which
// in a checked-out repository is never. This puts one wherever resolution
// reads a file: among a project's sources, as a manifest-less script, and
// under the names read directly rather than found by the walk (the server.json
// and Cargo.toml of an ancestor, a project's wrangler.toml, .gitmodules).
func TestResolve_FIFOsDoNotBlock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "server", "package.json"), `{"name": "server", "bin": "index.js", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
	writeFile(t, filepath.Join(root, "server", "index.ts"), `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; new McpServer();`)
	writeFile(t, filepath.Join(root, "tool", "package.json"), `{"name": "tool"}`)
	writeFile(t, filepath.Join(root, "crates", "c", "Cargo.toml"), "[package]\nname = \"c\"\n")
	for _, name := range []string{"server/handler.ts", "server.py", "server.json", "crates/Cargo.toml", "tool/wrangler.toml", ".gitmodules"} {
		if err := syscall.Mkfifo(filepath.Join(root, filepath.FromSlash(name)), 0o644); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
	}

	done := make(chan *Resolution, 1)
	go func() {
		resolution, err := Resolve(root)
		if err != nil {
			t.Errorf("Resolve returned error: %v", err)
		}
		done <- resolution
	}()
	select {
	case resolution := <-done:
		if resolution != nil && (len(resolution.Targets) != 1 || resolution.Targets[0].Name != "server") {
			t.Errorf("targets = %v, want only server", targetNames(resolution.Targets))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Resolve blocked reading a FIFO")
	}
}

func TestReadFileCapped_RejectsFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "package.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if _, err := readFileCapped(fifo); err == nil {
		t.Error("readFileCapped read a FIFO, want an error")
	}
}
