package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// reSqlText matches a sqlalchemy text() sink -- either qualified sqlalchemy.text(...) or a
// bare text(...) from a "from sqlalchemy import text" import -- but not another object's
// .text() method, nor gettext()/context() or pathlib read_text()/write_text().
var reSqlText = regexp.MustCompile(`(^|[^\w.])text\(|sqlalchemy\.text\(`)

// resultsToPaths converts decoded engine results into deduped taint paths. Every
// engine-supplied path is confined to root before any read, so a malformed path
// cannot make repo-scan read a file outside the scanned repo.
func resultsToPaths(out *ogOutput, root string) []PathRecord {
	seen := map[string]PathRecord{}
	order := []string{}
	// Cache each source file's lines so many results in one file don't re-read it.
	fileLines := map[string][]string{}
	for _, r := range out.Results {
		vc := vulnClassFromCheckID(r.CheckID)
		if vc == "" || r.Path == "" {
			continue
		}
		// Engine paths are normally absolute (we pass an absolute target), but root a
		// relative path at the scan root so confinement/reads never fall back to CWD.
		// filepath.IsAbs is GOOS-specific (false for "/etc/passwd" on Windows), so also
		// treat a leading / or \ as absolute -- otherwise a POSIX path from the engine
		// would be joined into root on Windows and slip past confinement.
		p := r.Path
		if !filepath.IsAbs(p) && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, `\`) {
			p = filepath.Join(root, p)
		}
		if !withinRoot(p, root) {
			continue
		}
		rel := relToRoot(p, root)
		mv := r.Extra.Metavars
		sinkSnippet := snippet(fileLines, p, r.Start.Line, max(r.Start.Line, r.End.Line))
		sinkAPI := canonicalSinkAPI(sinkSnippet)
		if sinkAPI == unknownSink {
			// focus-metavariable narrows the reported range to $SINK itself, so a call
			// split across lines --
			//     process = await asyncio.create_subprocess_shell(
			//         cmd,                 <-- $SINK: the range is just this line
			// -- yields a snippet with no api name in it. Widen UPWARD and retry.
			// Upward only, and never past the sink line: reading forward would pick up
			// the NEXT statement's api and mislabel the finding (a path_traversal
			// reported as os.system). If the widened window still has no api, keep
			// unknown rather than guessing.
			if w := snippet(fileLines, p, max(1, r.Start.Line-sinkLookback), r.Start.Line); w != "" {
				if a := canonicalSinkAPI(w); a != unknownSink {
					sinkAPI = a
				}
			}
		}
		sinkAPI = shellSuffixFromClass(vc, sinkAPI)
		sinkAPI = pathlibLabelFromClass(vc, sinkAPI, sinkSnippet)
		rec := PathRecord{
			VulnClass:      vc,
			SourceFile:     rel,
			SourceLine:     mv["$SRC"].Start.Line, // 0 (unknown) when $SRC has no position; never the sink line
			SourceFunction: firstNonEmpty(mv["$F"].AbstractContent, "unknown"),
			SourceParam:    firstNonEmpty(mv["$SRC"].AbstractContent, "unknown"),
			SinkFile:       rel,
			SinkLine:       r.Start.Line,
			SinkAPI:        sinkAPI,
			Engine:         "opengrep",
			RuleID:         r.CheckID,
			SinkSnippet:    strings.TrimSpace(sinkSnippet),
		}
		for _, iv := range r.Extra.DataflowTrace.IntermediateVars {
			if iv.Content != "" {
				rec.Steps = append(rec.Steps, clip(iv.Content, 160))
			}
		}
		id := rec.pathID()
		if _, ok := seen[id]; !ok {
			seen[id] = rec
			order = append(order, id)
		}
	}
	paths := make([]PathRecord, 0, len(order))
	for _, id := range order {
		paths = append(paths, seen[id])
	}
	return paths
}

// vulnClassFromCheckID recovers the class from a generated rule id
// (mcpxray-py-<class>), tolerating any namespace prefix the engine adds.
func vulnClassFromCheckID(checkID string) string {
	const marker = "mcpxray-py-"
	i := strings.LastIndex(checkID, marker)
	if i < 0 {
		return ""
	}
	return checkID[i+len(marker):]
}

// shelledSubprocessFns are the subprocess entry points whose OpenGrep command_injection
// patterns ALL require shell=True (see baseSinksPy). getoutput/getstatusoutput are absent
// deliberately: they are always shell-interpreted and carry no suffix in either engine.
var shelledSubprocessFns = map[string]bool{
	"subprocess.run": true, "subprocess.call": true, "subprocess.Popen": true,
	"subprocess.check_output": true, "subprocess.check_call": true,
}

// shellSuffixFromClass restores the "+shell=True" suffix that snippet recovery cannot see.
//
// The keyword sits BELOW the tainted argument:
//
//	subprocess.run(
//	    cmd,          <- $SINK; the focused range, and where the sink line points
//	    shell=True)   <- the evidence, one line further down
//
// The lookback is upward-only on purpose (reading forward steals the next statement's api),
// so the window legitimately cannot contain shell=True. But we do not need to read it: a
// command_injection finding from the generated OpenGrep rules can ONLY have matched a
// pattern that required shell=True, so the rule itself is the evidence.
//
// This exists so the label matches what the CodeQL pack emits -- SinkAPI is part of
// sinkIdentity, and a missing suffix silently splits one vulnerability into two reports.
// TestSinkAPILabelParity pins it.
func shellSuffixFromClass(vulnClass, api string) string {
	if vulnClass != "command_injection" || strings.HasSuffix(api, "+shell=True") {
		return api
	}
	if shelledSubprocessFns[api] {
		return api + "+shell=True"
	}
	return api
}

// pathlibLabelFromClass aligns the INLINE `Path(x).read_text()` / `.write_text()` form with
// the CodeQL pack, which has no read_text/write_text sink at all: its only pathlib sink is
// the `Path(...)` construction, so it labels that line `pathlib.Path`.
//
// This cannot live in canonicalSinkAPI's switch, because the same line can be two different
// sinks at once and only the vuln class distinguishes them:
//
//	data = eval(Path(name).read_text())
//
// is a code_injection at `eval` AND a path_traversal at the Path() construction. The switch
// sees one line and must pick one answer; it picks the enclosing call (`eval`), which is
// right for the code_injection finding. For the path_traversal finding on that same line the
// sink really is the Path() construction, and that is what this corrects.
//
// Only path_traversal is touched, and only when the inline read/write shape is present -- a
// line like `open(Path(base) / name)` has no read_text/write_text and keeps its `open`
// label, matching CodeQL.
//
// SinkAPI is part of sinkIdentity, so a disagreement here splits one vulnerability into two
// reports. TestSinkAPILabelParity pins the pair.
func pathlibLabelFromClass(vulnClass, api, snippet string) string {
	if vulnClass != "path_traversal" {
		return api
	}
	if !strings.Contains(snippet, "Path(") {
		return api
	}
	if strings.Contains(snippet, ".read_text(") || strings.Contains(snippet, ".write_text(") {
		return "pathlib.Path"
	}
	return api
}

// unknownSink is the SinkAPI used when no arm matches. It is part of pathID, so it
// must stay a single stable string.
const unknownSink = "unknown_sink"

// sinkLookback is how many lines above the reported sink line the api name is searched
// for when the focused range alone has none. 3 covers the common multi-line call
// (callee, then one or two args) without reaching into a previous statement.
const sinkLookback = 3

// canonicalSinkAPI maps a sink snippet to a stable API name.
func canonicalSinkAPI(code string) string {
	// Collapse all whitespace (incl. newlines/tabs from multi-line snippets) so the
	// contains-checks and resulting SinkAPI (part of pathID) stay stable.
	c := strings.Join(strings.Fields(code), "")
	switch {
	case strings.Contains(c, "os.system("):
		return "os.system"
	case strings.Contains(c, "os.popen("):
		return "os.popen"
	// asyncio's shell spawner. Matched on the bare name so both the qualified
	// (asyncio.create_subprocess_shell) and imported-bare forms canonicalise the same.
	// Must precede the generic subprocess arms: the snippet contains "subprocess" but
	// not "subprocess.", so it would otherwise fall through to the default and lose the
	// api name that MergePaths keys on.
	case strings.Contains(c, "create_subprocess_shell("):
		return "asyncio.create_subprocess_shell"
	case strings.Contains(c, "subprocess.getstatusoutput("):
		return "subprocess.getstatusoutput"
	case strings.Contains(c, "subprocess.getoutput("):
		return "subprocess.getoutput"
	case strings.Contains(c, "pty.spawn("):
		return "pty.spawn"
	case strings.Contains(c, "shell=True") && strings.Contains(c, "subprocess."):
		rest := strings.SplitN(c, "subprocess.", 2)[1]
		return "subprocess." + strings.SplitN(rest, "(", 2)[0] + "+shell=True"
	// Any other subprocess.* call. Must precede the generic `open(` case below, or
	// subprocess.Popen(...) matches it on the "open(" substring and a command-injection
	// finding is labelled with a file API. The CodeQL packs match these without
	// shell=True, so this arm is reachable even though opengrep only emits the form above.
	case strings.Contains(c, "subprocess."):
		rest := strings.SplitN(c, "subprocess.", 2)[1]
		return "subprocess." + strings.SplitN(rest, "(", 2)[0]
	case strings.Contains(c, ".executescript("):
		return "executescript"
	// executemany before the generic .execute( arm, which would otherwise shadow it.
	case strings.Contains(c, ".executemany("):
		return "cursor.executemany"
	case strings.Contains(c, ".execute("):
		return "cursor.execute"
	case strings.Contains(c, "urlopen("):
		return "urllib.urlopen"
	case strings.Contains(c, "requests.get("):
		return "requests.get"
	case strings.Contains(c, "requests.post("):
		return "requests.post"
	case strings.Contains(c, "requests.request("):
		return "requests.request"
	case strings.Contains(c, "httpx.get("):
		return "httpx.get"
	case strings.Contains(c, "httpx.post("):
		return "httpx.post"
	// The remaining verbs the CodeQL Python pack selects but the opengrep rules do not.
	case strings.Contains(c, "requests.put("), strings.Contains(c, "httpx.put("):
		return "http.put"
	case strings.Contains(c, "requests.delete("), strings.Contains(c, "httpx.delete("):
		return "http.delete"
	case strings.Contains(c, "requests.head("), strings.Contains(c, "httpx.head("):
		return "http.head"
	case strings.Contains(c, "requests.patch("), strings.Contains(c, "httpx.patch("):
		return "http.patch"
	// Generic HTTP client .request(url=...) sink (rules.go ssrf), after the named clients
	// above so those keep their precise labels.
	case strings.Contains(c, ".request("):
		return "http.request"
	// --- filesystem sinks the CodeQL Python pack selects. All must precede the generic
	// `open(` arm below: tarfile.open/zipfile.ZipFile contain it as a substring, and the
	// pathlib Path() construction is the sink node for the split `p = Path(x)` form that
	// the pack's own fixture (testdata/py-vuln read_split) exercises.
	case strings.Contains(c, "tarfile.open("):
		return "tarfile.open"
	case strings.Contains(c, "zipfile.ZipFile("):
		return "zipfile.ZipFile"
	case strings.Contains(c, "shutil."):
		rest := strings.SplitN(c, "shutil.", 2)[1]
		return "shutil." + strings.SplitN(rest, "(", 2)[0]
	case strings.Contains(c, "os.remove("), strings.Contains(c, "os.unlink("):
		return "os.remove"
	case strings.Contains(c, "os.mkdir("), strings.Contains(c, "os.makedirs("):
		return "os.mkdir"
	case strings.Contains(c, "os.rmdir("):
		return "os.rmdir"
	case strings.Contains(c, "io.open("):
		return "io.open"
	case strings.Contains(c, "os.open("):
		return "os.open"
	case strings.Contains(c, "codecs.open("):
		return "codecs.open"
	// The ENCLOSING call wins. A snippet is one line and a line can mention several sink
	// names, so the arms below are ordered outermost-first: `open(Path(base) / name)` is an
	// open() sink whose argument merely happens to be built with Path(), and CodeQL labels
	// it `open`. A bare `Path(` test placed above `open(` claimed that line for pathlib and
	// split the finding across engines -- one vulnerability reported twice, which is the
	// failure sinkIdentity exists to prevent.
	//
	// `Path(` is therefore LAST of this group: it only claims a line where nothing encloses
	// it, i.e. the two-statement `p = Path(x)` form whose read is on another line.
	// The inline `Path(x).read_text()` form is handled by pathlibLabelFromClass, which needs
	// the vuln class to decide and so cannot live in this switch.
	case strings.Contains(c, "open("):
		return "open"
	case strings.Contains(c, "eval("):
		return "eval"
	case strings.Contains(c, "exec("):
		return "exec"
	case strings.Contains(c, ".read_text("):
		return "pathlib.read_text"
	case strings.Contains(c, ".write_text("):
		return "pathlib.write_text"
	case strings.Contains(c, "Path("):
		return "pathlib.Path"
	// Checked last so a specific sink wrapping a text() arg (requests.get(text(u)),
	// session.execute(text(q))) is labeled by that sink; only a standalone sqlalchemy.text
	// or a bare `from sqlalchemy import text` call lands here.
	case reSqlText.MatchString(c):
		return "sqlalchemy.text"
	}
	return unknownSink
}

// withinRoot reports whether p resolves to a location inside root. Symlinks are
// resolved first, so an in-repo symlink pointing outside cannot pass the check and
// trick snippet into reading a host file outside the scanned repo.
func withinRoot(p, root string) bool {
	rel, err := filepath.Rel(resolvePath(root), resolvePath(p))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolvePath returns the absolute, symlink-resolved path, falling back to the plain
// absolute form when the path does not exist (nothing to read there anyway).
func resolvePath(p string) string {
	ap, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(ap); err == nil {
		return r
	}
	return ap
}

func relToRoot(p, root string) string {
	ap, _ := filepath.Abs(p)
	ar, _ := filepath.Abs(root)
	rel, err := filepath.Rel(ar, ap)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.Base(p)
	}
	return filepath.ToSlash(rel)
}

// snippet returns the trimmed source lines [start,end], reading each file at most
// once per scan via cache (nil entry negative-caches an unreadable path).
func snippet(cache map[string][]string, path string, start, end int) string {
	if start <= 0 {
		return ""
	}
	lines, ok := cache[path]
	if !ok {
		data, err := os.ReadFile(path)
		if err != nil {
			cache[path] = nil
			return ""
		}
		lines = strings.Split(string(data), "\n")
		cache[path] = lines
	}
	if len(lines) == 0 || start > len(lines) {
		return ""
	}
	if end > len(lines) {
		end = len(lines)
	}
	return strings.TrimSpace(strings.Join(lines[start-1:end], "\n"))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
