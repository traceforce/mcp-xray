package targetresolve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan"

	toml "github.com/pelletier/go-toml/v2"
)

// manifestConstructors maps a manifest basename to the ecosystem-specific
// constructor that turns it into a Project. Ecosystems whose manifest
// filename is fixed (go.mod, package.json, pyproject.toml, pom.xml,
// Cargo.toml) are matched here by exact name. .csproj is handled separately
// in discoverProjects below (see newDotnetProject) because its filename
// varies per project (e.g. Fabric.Mcp.Server.csproj), so it can't be a map
// key. newRustProject can return (nil, nil) for a Cargo.toml that declares
// no [package] (a virtual workspace-root manifest); discoverProjects skips
// a nil project like a malformed manifest.
var manifestConstructors = map[string]func(manifestPath string) (*Project, error){
	"go.mod":         newGoProject,
	"package.json":   newNodeProject,
	"pyproject.toml": newPythonProject,
	"pom.xml":        newJavaProject,
	"Cargo.toml":     newRustProject,
}

// discoverProjects returns one Project per ecosystem manifest under
// repoRoot, with Role left unset: classification needs every project, so it
// runs as a separate pass. A directory can hold several projects (say, a
// Python package inside a Node monorepo), so a manifest never stops the walk
// from descending further. A malformed manifest is skipped, not fatal.
func discoverProjects(repoRoot string) ([]*Project, error) {
	var projects []*Project
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		constructor, ok := manifestConstructors[info.Name()]
		if !ok {
			if !strings.HasSuffix(info.Name(), ".csproj") {
				return nil
			}
			constructor = newDotnetProject
		}
		project, err := constructor(path)
		if err != nil || project == nil {
			return nil
		}
		project.RelDir = repoRelative(repoRoot, project.Dir)
		projects = append(projects, project)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

// walkFiles calls visit for every regular file under root, skipping the
// directories the scanners skip by default (reposcan.DefaultExcludedDirs)
// and any directory skipDir reports (nil skips none). Symlinks, FIFOs and
// devices are never visited, as the SAST scanner skips them too: reading a
// FIFO blocks forever, and a symlink can lead to /dev/zero or out of the
// repository. Unreadable entries are skipped rather than aborting the walk;
// visit may return filepath.SkipAll to stop early.
func walkFiles(root string, skipDir func(dir string) bool, visit func(path string, info os.FileInfo) error) error {
	return walk(root, false, skipDir, visit)
}

// walkSourceFiles is walkFiles for reading a project's source to classify
// it, which also enters src/bin: "bin" is a build output elsewhere, but
// under src it holds source -- Cargo builds every src/bin/*.rs as a binary,
// so a Rust server's main often lives there. The scanners still skip it, so
// it stays out of the inventory and of every scan unit's files.
func walkSourceFiles(root string, skipDir func(dir string) bool, visit func(path string, info os.FileInfo) error) error {
	return walk(root, true, skipDir, visit)
}

func walk(root string, enterSourceBin bool, skipDir func(dir string) bool, visit func(path string, info os.FileInfo) error) error {
	// A walk prunes a directory the moment it reaches it, so only each
	// entry's own name needs checking.
	defaults := &reposcan.Config{ExcludedPaths: reposcan.DefaultExcludedDirs()}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		switch {
		case err != nil:
			return nil
		case info.IsDir():
			if path == root {
				return nil // the walk's root is never pruned, whatever its name
			}
			if (defaults.ShouldExclude(info.Name()) && !(enterSourceBin && isSourceBinDir(path))) || (skipDir != nil && skipDir(path)) {
				return filepath.SkipDir
			}
			return nil
		case !info.Mode().IsRegular(), defaults.ShouldExclude(info.Name()):
			return nil // filepath.Walk reports a symlink itself, never its target
		}
		return visit(path, info)
	})
}

// maxReadFileSize caps every file target resolution reads at the scanners'
// default --max-file-size: a file the scanners would skip is no evidence of
// what a project is, and reading one whole could exhaust memory.
var maxReadFileSize = reposcan.DefaultConfig().MaxFileSize

// readFileCapped reads the file at path, following symlinks, when it is a
// regular file of at most maxReadFileSize bytes, and fails otherwise. Every
// manifest and source read goes through it: walkFiles only visits regular
// files, but manifests are also read by name (an ancestor's Cargo.toml, a
// server.json, a script a package.json runs), and a FIFO there would block
// the reader forever.
func readFileCapped(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxReadFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxReadFileSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxReadFileSize)) // in case it grew since
}

// utf8BOM is the byte order mark some editors write at the start of a UTF-8
// file. JSON does not allow one, but npm and the tools reading these
// manifests skip it.
var utf8BOM = []byte("\xef\xbb\xbf")

// readJSONFile unmarshals the JSON file at path into v, past a leading byte
// order mark: a package.json or server.json saved with one is still the
// project's manifest.
func readJSONFile(path string, v any) error {
	data, err := readFileCapped(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), v)
}

// maxTOMLFileSize and maxTOMLNesting bound the TOML manifests target
// resolution parses (pyproject.toml, Cargo.toml, wrangler.toml). The parser
// recurses once per nested array or inline table, without limit, and takes
// time quadratic in a document's size: a hostile manifest of nested arrays
// overflows the stack, which kills the process outright, and a large one
// stalls resolution. A real manifest is a few kilobytes deep in single
// digits; the largest among 17 MCP repositories is 14 KB.
const (
	maxTOMLFileSize = 256 << 10
	maxTOMLNesting  = 64
)

// readTOMLFile unmarshals the TOML file at path into v, refusing a file
// beyond maxTOMLFileSize or nested beyond maxTOMLNesting.
func readTOMLFile(path string, v any) error {
	data, err := readFileCapped(path)
	if err != nil {
		return err
	}
	if len(data) > maxTOMLFileSize {
		return fmt.Errorf("%s is larger than %d bytes", path, maxTOMLFileSize)
	}
	if tomlNesting(data) > maxTOMLNesting {
		return fmt.Errorf("%s nests arrays or tables deeper than %d", path, maxTOMLNesting)
	}
	return toml.Unmarshal(data, v)
}

// tomlNesting returns how deeply data nests brackets and braces outside
// strings and comments: an upper bound on the parser's recursion. A table
// header ([a], [[a]]) opens and closes on its line, so it adds little.
func tomlNesting(data []byte) int {
	depth, deepest := 0, 0
	for i := 0; i < len(data); i++ {
		switch c := data[i]; c {
		case '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case '"', '\'':
			i = endOfTOMLString(data, i)
		case '[', '{':
			if depth++; depth > deepest {
				deepest = depth
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return deepest
}

// endOfTOMLString returns the index of the last byte of the string that
// starts at data[start] (a quote): basic ("...") and literal ('...')
// strings, single-line or triple-quoted, where only a basic string has
// backslash escapes. An unterminated string runs to the end of data.
func endOfTOMLString(data []byte, start int) int {
	quote := data[start]
	delimiter := []byte{quote}
	if bytes.HasPrefix(data[start:], []byte{quote, quote, quote}) {
		delimiter = []byte{quote, quote, quote}
	}
	for i := start + len(delimiter); i < len(data); i++ {
		if quote == '"' && data[i] == '\\' {
			i++
			continue
		}
		if bytes.HasPrefix(data[i:], delimiter) {
			return i + len(delimiter) - 1
		}
	}
	return len(data) - 1
}

func isSourceBinDir(dir string) bool {
	return filepath.Base(dir) == "bin" && filepath.Base(filepath.Dir(dir)) == "src"
}
