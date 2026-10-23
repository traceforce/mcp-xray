package libmcp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stdioExitWait is how long a child gets to exit after stdin closes, then
// after SIGTERM, then after SIGKILL; mcp.CommandTransport uses the same value.
// It is also cmd.WaitDelay, which bounds Wait when a grandchild keeps the
// stderr pipe open.
const stdioExitWait = 5 * time.Second

// stderrTail bounds: enough to keep the last error a package manager prints
// without flooding the outcome reason.
const (
	stderrTailBytes = 2048
	stderrTailLines = 10
)

// startStdio starts cmd and returns a transport over its pipes. The SDK's
// CommandTransport hands stdout straight to its JSON decoder, so a server that
// prints a banner before its first message fails initialize; jsonLines keeps
// only the JSON lines.
func startStdio(cmd *exec.Cmd) (mcp.Transport, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &mcp.IOTransport{
		// The connection is closed through stdin; stdout is closed by Wait.
		Reader: io.NopCloser(&jsonLines{r: bufio.NewReader(stdout)}),
		Writer: &stdinCloser{WriteCloser: stdin, cmd: cmd},
	}, nil
}

// jsonLines passes through the lines of r whose first non-blank byte is '{'
// and drops the rest. That includes '[' batches: this client never sends one,
// and "[INFO]" log prefixes are common.
type jsonLines struct {
	r    *bufio.Reader
	line []byte // unread rest of the current JSON line
	err  error  // returned once line is drained
}

func (l *jsonLines) Read(p []byte) (int, error) {
	for len(l.line) == 0 {
		if l.err != nil {
			return 0, l.err
		}
		l.line, l.err = l.r.ReadBytes('\n')
		if first := bytes.TrimLeft(l.line, " \t"); len(first) == 0 || first[0] != '{' {
			l.line = nil
		}
	}
	n := copy(p, l.line)
	l.line = l.line[n:]
	return n, nil
}

// stdinCloser closes the child's stdin and then waits for it to exit,
// escalating to SIGTERM and SIGKILL as mcp.CommandTransport does.
type stdinCloser struct {
	io.WriteCloser
	cmd *exec.Cmd
}

func (c *stdinCloser) Close() error {
	if err := c.WriteCloser.Close(); err != nil {
		return fmt.Errorf("closing stdin: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	for _, stop := range []func() error{
		func() error { return nil },
		func() error { return c.cmd.Process.Signal(syscall.SIGTERM) },
		c.cmd.Process.Kill,
	} {
		if err := stop(); errors.Is(err, os.ErrProcessDone) {
			return <-done // exited while Wait was still draining its pipes
		} else if err != nil {
			continue // SIGTERM is not supported on every platform; go on to SIGKILL
		}
		select {
		case err := <-done:
			return err
		case <-time.After(stdioExitWait):
		}
	}
	return errors.New("unresponsive subprocess")
}

// stderrTail keeps the end of what a child writes to stderr so a connect
// failure can say why the child exited.
type stderrTail struct {
	mu  sync.Mutex // Close can report an unresponsive child while Wait's copy goroutine still writes
	buf []byte
}

func (t *stderrTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if drop := len(t.buf) - stderrTailBytes; drop > 0 {
		t.buf = t.buf[drop:]
	}
	return len(p), nil
}

// String returns the last stderrTailLines lines written, without surrounding whitespace.
func (t *stderrTail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(t.buf)), "\n")
	if len(lines) > stderrTailLines {
		lines = lines[len(lines)-stderrTailLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
