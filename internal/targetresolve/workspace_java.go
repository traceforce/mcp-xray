package targetresolve

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// pomXML is the minimal shape of a Maven pom.xml needed by this package:
// its own coordinates (groupId/artifactId, with a parent-groupId fallback --
// a standard Maven convention where a child module inherits groupId from
// <parent> when it declares none of its own; proactive, not evidenced by
// oracle/mcp's real pom.xml, which declares its own groupId directly) and
// its <dependencies> (for SDK detection and local-dependency resolution).
// The "dependencies>dependency" path deliberately only matches the
// top-level <dependencies> element, not the version-constraint-only
// <dependencyManagement><dependencies> block, which is a different parent
// element and is never confused with real runtime dependencies here.
type pomXML struct {
	XMLName       xml.Name        `xml:"project"`
	GroupID       string          `xml:"groupId"`
	ArtifactID    string          `xml:"artifactId"`
	ParentGroupID string          `xml:"parent>groupId"`
	Dependencies  []pomDependency `xml:"dependencies>dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

// readPom centralizes the read+parse boilerplate, mirroring readCsproj.
func readPom(manifestPath string) (*pomXML, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var doc pomXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// effectiveGroupID returns the module's own groupId, falling back to its
// parent POM's groupId.
func (doc *pomXML) effectiveGroupID() string {
	if doc.GroupID != "" {
		return doc.GroupID
	}
	return doc.ParentGroupID
}

// newJavaProject builds a Project from a discovered pom.xml file. Name
// prefers artifactId -- Maven's own conventional module identifier,
// confirmed by oracle/mcp's real oracle-db-mcp-toolkit
// (artifactId=oracle-db-mcp-toolkit) -- falling back to the directory
// basename for a pom.xml that parsed but declares no artifactId.
func newJavaProject(manifestPath string) (*Project, error) {
	doc, err := readPom(manifestPath)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(manifestPath)
	name := doc.ArtifactID
	if name == "" {
		name = filepath.Base(dir)
	}

	return &Project{
		Name:         name,
		Dir:          dir,
		Ecosystem:    "java",
		ManifestPath: manifestPath,
	}, nil
}

// javaGroupIDDependency reports whether doc has a dependency whose groupId
// equals prefix or starts with prefix+".", the same prefix-matching
// convention already used for .NET (dotnetPackageReferencePrefix) and Go
// (module-path prefix match). Confirmed necessary by oracle/mcp's real
// dependency: groupId "io.modelcontextprotocol.sdk", artifactId "mcp".
func javaGroupIDDependency(doc *pomXML, groupIDPrefix string) bool {
	for _, dep := range doc.Dependencies {
		if dep.GroupID == groupIDPrefix || strings.HasPrefix(dep.GroupID, groupIDPrefix+".") {
			return true
		}
	}
	return false
}

// resolveJavaLocalDeps fills in LocalDeps for every discovered Java project
// by matching each <dependency>'s groupId:artifactId against another
// discovered Java project's own effective coordinates. Maven has no
// file-path-based local-dependency mechanism analogous to Node's
// file:/link: protocols or .NET's ProjectReference -- a local module
// dependency is expressed exactly like a Maven Central one, distinguished
// only by whether its coordinates happen to resolve to a module physically
// present in this repo. This mirrors the same accepted-tradeoff pattern
// already used for Go (a require entry matching a known local module path
// needs no replace directive) and Node (a plain-version dependency matching
// a local project's declared name): a same-coordinate collision with an
// unrelated registry-published artifact is possible in theory, not solvable
// without a Maven Central lookup, and no repo examined this session shows
// it causing a real false positive.
func resolveJavaLocalDeps(projects []*Project) {
	byCoordinate := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem != "java" {
			continue
		}
		doc, err := readPom(p.ManifestPath)
		if err != nil {
			continue
		}
		if coord := javaCoordinate(doc.effectiveGroupID(), doc.ArtifactID); coord != "" {
			byCoordinate[coord] = p
		}
	}
	if len(byCoordinate) == 0 {
		return
	}

	for _, p := range projects {
		if p.Ecosystem != "java" {
			continue
		}
		doc, err := readPom(p.ManifestPath)
		if err != nil {
			continue
		}
		for _, dep := range doc.Dependencies {
			coord := javaCoordinate(dep.GroupID, dep.ArtifactID)
			if coord == "" {
				continue
			}
			if target, ok := byCoordinate[coord]; ok && target != p {
				addLocalDep(p, target.Dir)
			}
		}
	}
}

func javaCoordinate(groupID, artifactID string) string {
	if groupID == "" || artifactID == "" {
		return ""
	}
	return groupID + ":" + artifactID
}
