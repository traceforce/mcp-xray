package libmcp

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestRedirectServerIgnoresWrongState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	codeCh, errCh := make(chan string, 1), make(chan string, 1)
	shutdown := startRedirectServer(codeCh, errCh, "127.0.0.1", port, "mine")
	defer shutdown()
	callback := func(query string) int {
		t.Helper()
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s?%s", port, RedirectPath, query))
		if err != nil {
			t.Fatalf("callback %s: %v", query, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Stop at the first leak: a second send on a full channel would block the handler.
	for _, q := range []string{"code=c&state=theirs", "error=access_denied&state=theirs", "code=c"} {
		if got := callback(q); got != http.StatusBadRequest || len(codeCh) != 0 || len(errCh) != 0 {
			t.Fatalf("callback %s = %d with codes=%d errors=%d, want 400 and nothing sent", q, got, len(codeCh), len(errCh))
		}
	}

	if got := callback("code=c&state=mine"); got != http.StatusOK || len(codeCh) != 1 || <-codeCh != "c" {
		t.Fatalf("callback with this login's state = %d, want 200 and code c", got)
	}
}
