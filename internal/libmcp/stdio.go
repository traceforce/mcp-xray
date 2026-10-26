package libmcp

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	"unicode/utf16"
	"unicode/utf8"

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
// prints a banner before its first message fails initialize; jsonLines writes
// what comes before the first message to dropped and passes the rest through.
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

// jsonLines drops what a child prints before its first JSON-RPC message: each
// line whose first non-blank byte is not '{' (or "[{", a batch), and a UTF-8
// BOM, chunk by chunk, so progress output without newlines cannot grow memory.
// From the first message on, stdout passes through as is, as at base: a
// pretty-printed message decodes whole, and later non-JSON output fails the
// call at once instead of being dropped together with a response.
type jsonLines struct {
	r       *bufio.Reader
	dropped io.Writer // what was dropped, for the diagnostic tail (masked by redact)
	mid     bool      // inside a dropped line
	started bool      // the first message began
}

func (l *jsonLines) Read(p []byte) (int, error) {
	for !l.started {
		if !l.mid {
			if bom, _ := l.r.Peek(3); string(bom) == "\xef\xbb\xbf" {
				_, _ = l.r.Discard(3)
			}
			b, err := l.r.ReadByte()
			if err != nil {
				return 0, err
			}
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
				_, _ = l.dropped.Write([]byte{b}) // blank lines and indent: keep the diagnostic faithful
				continue
			}
			_ = l.r.UnreadByte()
			if next, _ := l.r.Peek(2); next[0] == '{' || string(next) == "[{" {
				l.started = true
				continue
			}
			l.mid = true
		}
		chunk, err := l.r.ReadSlice('\n')
		_, _ = l.dropped.Write(chunk)
		if err == nil {
			l.mid = false
		} else if err != bufio.ErrBufferFull {
			return 0, err
		}
	}
	return l.r.Read(p)
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
// 8 bytes or more: every argument but a bare flag name, the argument after a
// flag even when it starts with a single '-', and the valueParts of each.
// ponytail: an attached value (-pVALUE) is not split off; Go-style -transport
// flags would mask ordinary words.
func argSecrets(args []string) []string {
	var secrets []string
	add := func(v string) {
		if len(v) >= 8 {
			secrets = append(secrets, v)
		}
	}
	flagValue := false // the previous argument was a flag name, so this one is its value
	for _, arg := range args {
		isFlag := strings.HasPrefix(arg, "-") && !strings.Contains(arg, "=")
		// "--" after a flag is the next flag, the first one being boolean.
		if !isFlag || (flagValue && !strings.HasPrefix(arg, "--")) {
			add(arg)
		}
		flagValue = isFlag
		for _, part := range valueParts(arg) {
			add(part)
		}
	}
	return secrets
}

// valueParts returns the parts of a value that may be a credential on their own:
// the part after '=' in each '&'-separated piece, the last word of a value with
// spaces ("Bearer <token>"), and a URL's user and password, as written and decoded.
func valueParts(v string) []string {
	var parts []string
	if _, value, ok := strings.Cut(v, "="); ok {
		parts = append(parts, value) // --password=a&b: the whole value too
	}
	for _, piece := range strings.Split(v, "&") {
		if _, value, ok := strings.Cut(piece, "="); ok {
			parts = append(parts, value)
		}
	}
	if words := strings.Fields(v); len(words) > 1 {
		parts = append(parts, words[len(words)-1])
	}
	for _, rest := range strings.Split(v, "://")[1:] {
		authority := rest
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			authority = rest[:i] // userinfo lives before the path, query or fragment
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			user, pass, _ := strings.Cut(authority[:at], ":")
			for _, s := range []string{user, pass} {
				parts = append(parts, s)
				if dec, err := url.PathUnescape(s); err == nil && dec != s { // a child may log the decoded form
					parts = append(parts, dec)
				}
			}
		}
	}
	return parts
}

// remoteSecrets returns the masking candidates of a remote config: its URL and
// header values, whole and in parts.
func remoteSecrets(rawURL string, headers map[string]string) []string {
	values := []string{rawURL}
	for _, v := range headers {
		values = append(values, v)
	}
	var all []string
	for _, v := range values {
		all = append(append(all, v), valueParts(v)...)
	}
	return secretParts(all)
}

// secretParts returns the values to mask, each without surrounding whitespace
// (a child that trims a value before logging it must still match, and a
// trailing newline must not join two reason lines): each value, its lines when
// it spans several (jsonLines may route them to the diagnostic separately), and
// the JSON-escaped forms of each, since a child that logs structured JSON emits a
// value with its quotes, backslashes and newlines escaped.
func secretParts(values []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		if len(v) < 8 || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	addForms := func(v string) {
		v = strings.TrimSpace(v)
		add(v)
		for _, esc := range jsonEscapes(v) {
			add(esc)
		}
	}
	for _, v := range values {
		addForms(v)
		if strings.Contains(v, "\n") {
			for _, line := range strings.Split(v, "\n") {
				addForms(line)
			}
		}
	}
	return out
}

// jsonEscapes returns the quoted bodies a JSON logger may print for v: Go's
// json.Marshal (&, < and > escaped), Node's JSON.stringify and Go's slog (those
// left raw), and Python's json.dumps (non-ASCII escaped as \uXXXX).
func jsonEscapes(v string) []string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil
	}
	raw := strings.TrimSuffix(buf.String(), "\n")
	raw = raw[1 : len(raw)-1]
	var ascii strings.Builder
	for _, r := range raw {
		if r < utf8.RuneSelf {
			ascii.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&ascii, `\u%04x`, u)
		}
	}
	html, _ := json.Marshal(v)
	return []string{string(html[1 : len(html)-1]), raw, ascii.String()}
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
