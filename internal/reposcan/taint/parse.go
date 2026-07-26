package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// reSqlText matches a standalone sqlalchemy text() call: a word boundary before `text(`
// so `gettext(`, `context(`, and pathlib `read_text(`/`write_text(` are not mislabeled.
var reSqlText = regexp.MustCompile(`\btext\(`)

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
		rec := PathRecord{
			VulnClass:      vc,
			SourceFile:     rel,
			SourceLine:     mv["$SRC"].Start.Line, // 0 (unknown) when $SRC has no position; never the sink line
			SourceFunction: firstNonEmpty(mv["$F"].AbstractContent, "unknown"),
			SourceParam:    firstNonEmpty(mv["$SRC"].AbstractContent, "unknown"),
			SinkFile:       rel,
			SinkLine:       r.Start.Line,
			SinkAPI:        canonicalSinkAPI(sinkSnippet),
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
	case strings.Contains(c, "shell=True") && strings.Contains(c, "subprocess."):
		rest := strings.SplitN(c, "subprocess.", 2)[1]
		return "subprocess." + strings.SplitN(rest, "(", 2)[0] + "+shell=True"
	case strings.Contains(c, ".executescript("):
		return "executescript"
	case strings.Contains(c, ".execute("):
		return "cursor.execute"
	// sqlalchemy text() sink for any argument; the word boundary excludes gettext/context
	// and pathlib read_text/write_text (they keep their own cases below).
	case reSqlText.MatchString(c):
		return "sqlalchemy.text"
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
	case strings.Contains(c, "io.open("):
		return "io.open"
	case strings.Contains(c, "os.open("):
		return "os.open"
	case strings.Contains(c, "codecs.open("):
		return "codecs.open"
	case strings.Contains(c, ".read_text("):
		return "pathlib.read_text"
	case strings.Contains(c, ".write_text("):
		return "pathlib.write_text"
	case strings.Contains(c, "open("):
		return "open"
	case strings.Contains(c, "eval("):
		return "eval"
	case strings.Contains(c, "exec("):
		return "exec"
	}
	return "unknown_sink"
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
