package libmcp

import (
	"bufio"
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
// and drops the rest, chunk by chunk, so a child that streams progress output
// without newlines cannot grow memory. Dropped lines include '[' batches: this
// client never sends one, and "[INFO]" log prefixes are common.
type jsonLines struct {
	r    *bufio.Reader
	mid  bool   // inside a line whose fate is decided
	keep bool   // and that line is JSON
	rest []byte // unread part of the current kept chunk
	err  error  // returned once rest is drained
}

func (l *jsonLines) Read(p []byte) (int, error) {
	for len(l.rest) == 0 {
		if l.err != nil {
			return 0, l.err
		}
		if !l.mid {
			b, err := l.r.ReadByte()
			if err != nil {
				l.err = err
				continue
			}
			if b == ' ' || b == '\t' || b == '\n' {
				continue // leading blanks and empty lines: the decoder would skip them too
			}
			l.mid, l.keep = true, b == '{'
			if l.keep {
				_ = l.r.UnreadByte()
			}
		}
		chunk, err := l.r.ReadSlice('\n')
		switch err {
		case nil:
			l.mid = false
		case bufio.ErrBufferFull:
		default:
			l.err = err // EOF or a read error, after the chunk is delivered
		}
		if l.keep {
			l.rest = append(l.rest[:0], chunk...)
		}
	}
	n := copy(p, l.rest)
	l.rest = l.rest[n:]
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
// failure can say why the child exited. The configured secrets are masked
// before the tail is cut to its last lines, so no fragment of one survives.
type stderrTail struct {
	secrets []string   // configured values that must never appear in a report
	mu      sync.Mutex // Close can report an unresponsive child while Wait's copy goroutine still writes
	buf     []byte
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

// String returns the last stderrTailLines lines written, with secrets masked
// and without surrounding whitespace.
func (t *stderrTail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(redact(string(t.buf), t.secrets)), "\n")
	if len(lines) > stderrTailLines {
		lines = lines[len(lines)-stderrTailLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// redact replaces every occurrence of the secrets in s with one "[redacted]"
// per masked span, so overlapping matches cannot leave a piece of each other
// behind. A leading suffix of a secret is masked too: s may start inside one
// that Write cut when the buffer filled.
func redact(s string, secrets []string) string {
	if len(secrets) == 0 {
		return s
	}
	masked := make([]bool, len(s))
	mark := func(from, to int) {
		for i := from; i < to; i++ {
			masked[i] = true
		}
	}
	for _, secret := range secrets {
		for i := 0; i < len(s); {
			j := strings.Index(s[i:], secret)
			if j < 0 {
				break
			}
			mark(i+j, i+j+len(secret))
			i += j + 1
		}
		for k := 1; k < len(secret); k++ {
			if strings.HasPrefix(s, secret[k:]) {
				mark(0, len(secret)-k)
				break
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !masked[i] {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString("[redacted]")
		for i < len(s) && masked[i] {
			i++
		}
	}
	return b.String()
}
