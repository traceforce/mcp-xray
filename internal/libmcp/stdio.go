package libmcp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
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
const stdioExitWait = 5 * time.Second

// stdioPipeWait is cmd.WaitDelay: once the child exits its output is already in
// the pipes, so a grandchild that keeps stderr open delays Wait by this much only.
const stdioPipeWait = 500 * time.Millisecond

// outputTail bounds: enough to keep the last error a package manager prints
// without flooding the outcome reason.
const (
	outputTailBytes = 2048
	outputTailLines = 10
)

// startStdio starts cmd and returns a transport over its pipes. The SDK's
// CommandTransport hands stdout straight to its JSON decoder, so a server that
// prints a banner before its first message fails initialize; jsonLines keeps
// only the JSON lines and writes the others to dropped.
func startStdio(cmd *exec.Cmd, dropped io.Writer) (mcp.Transport, error) {
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
		Reader: io.NopCloser(&jsonLines{r: bufio.NewReader(stdout), dropped: dropped}),
		Writer: &stdinCloser{WriteCloser: stdin, cmd: cmd},
	}, nil
}

// jsonLines passes through the lines of r whose first non-blank byte is '{'
// and drops the rest, chunk by chunk, so a child that streams progress output
// without newlines cannot grow memory. Dropped lines include '[' batches: this
// client never sends one, and "[INFO]" log prefixes are common.
type jsonLines struct {
	r       *bufio.Reader
	dropped io.Writer // receives the dropped lines, when set
	skipped []byte    // leading blanks of the current line, kept for a dropped line
	mid     bool      // inside a line whose fate is decided
	keep    bool      // and that line is JSON
	rest    []byte    // unread part of the current kept chunk
	err     error     // returned once rest is drained
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
			if b == '\r' || b == '\n' {
				l.skipped = l.skipped[:0] // an empty line carries nothing to report
				continue
			}
			if b == ' ' || b == '\t' {
				l.skipped = append(l.skipped, b) // indent of this line; the decoder skips it
				continue
			}
			l.mid, l.keep = true, b == '{'
			_ = l.r.UnreadByte()
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
		} else if l.dropped != nil {
			// A dropped line's indent is written too, so a secret spanning lines
			// stays byte-for-byte what the child wrote and redaction still matches.
			_, _ = l.dropped.Write(l.skipped)
			_, _ = l.dropped.Write(chunk)
		}
		l.skipped = l.skipped[:0]
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
	for i, stop := range []func() error{
		func() error { return nil },
		func() error { return c.cmd.Process.Signal(syscall.SIGTERM) },
		c.cmd.Process.Kill,
	} {
		err := stop()
		if errors.Is(err, os.ErrProcessDone) {
			return <-done // exited while Wait was still draining its pipes
		}
		if err != nil && i == 1 {
			continue // SIGTERM is not supported on every platform; go on to SIGKILL
		}
		// A Kill error can mean the child just exited, so it still waits.
		select {
		case err := <-done:
			return err
		case <-time.After(stdioExitWait):
		}
	}
	return errors.New("unresponsive subprocess")
}

// outputTail keeps the end of a child's stderr, or of the stdout lines
// jsonLines drops, so a connect failure can say why the child exited. The
// secrets are masked before the tail is cut to its last lines, so no fragment
// of one survives.
type outputTail struct {
	secrets []string   // environment and argument values that must never appear in a report
	mu      sync.Mutex // Close can report an unresponsive child while Wait's copy goroutine still writes
	buf     []byte
	cut     bool // buf lost its front and may start inside a secret
}

func (t *outputTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if drop := len(t.buf) - outputTailBytes; drop > 0 {
		t.buf, t.cut = t.buf[drop:], true
	}
	return len(p), nil
}

// String returns the last outputTailLines lines written, with secrets masked
// and without surrounding whitespace.
func (t *outputTail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(redact(string(t.buf), t.secrets, t.cut)), "\n")
	if len(lines) > outputTailLines {
		lines = lines[len(lines)-outputTailLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// argSecrets returns the parts of a command line that may carry a credential,
// 8 bytes or more: every argument but a bare flag name, the part after '=' in
// one, and a URL's user and password.
func argSecrets(args []string) []string {
	var secrets []string
	add := func(v string) {
		if len(v) >= 8 {
			secrets = append(secrets, v)
		}
	}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
			add(arg)
		}
		if _, value, ok := strings.Cut(arg, "="); ok {
			add(value)
		}
		for _, rest := range strings.Split(arg, "://")[1:] {
			authority, _, _ := strings.Cut(rest, "/")
			if at := strings.LastIndex(authority, "@"); at >= 0 {
				user, pass, _ := strings.Cut(authority[:at], ":")
				for _, v := range []string{user, pass} {
					add(v)
					// A child may log the decoded form, so mask that too.
					if dec, err := url.PathUnescape(v); err == nil && dec != v {
						add(dec)
					}
				}
			}
		}
	}
	return secrets
}

// redactedError reports msg, err's text with the child's secrets masked, and
// unwraps to err so errors.Is and errors.As still reach it.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redact replaces every occurrence of the secrets in s with one "[redacted]"
// per masked span, so overlapping matches cannot leave a piece of each other
// behind. With cut, a leading suffix of a secret is masked too: s then starts
// where the front of the buffer was dropped, possibly inside a secret.
func redact(s string, secrets []string, cut bool) string {
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
		for k := 1; cut && k < len(secret); k++ {
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
