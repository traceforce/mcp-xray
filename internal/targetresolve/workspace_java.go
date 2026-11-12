package targetresolve

import (
	"encoding/xml"
	"path/filepath"
	"strings"
)

// pomXML is the part of a Maven pom.xml this package reads: the module's
// own coordinates (a child module without a groupId inherits its
// <parent>'s) and its <dependencies>, for SDK detection and local
// dependency resolution. The "dependencies>dependency" path matches only
// the top-level <dependencies> element, never the version constraints in
// <dependencyManagement>.
type pomXML struct {
	XMLName          xml.Name        `xml:"project"`
	GroupID          string          `xml:"groupId"`
	ArtifactID       string          `xml:"artifactId"`
	ParentGroupID    string          `xml:"parent>groupId"`
	ParentArtifactID string          `xml:"parent>artifactId"`
	Dependencies     []pomDependency `xml:"dependencies>dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

// readPom centralizes the read+parse boilerplate, mirroring readCsproj.
func readPom(manifestPath string) (*pomXML, error) {
	data, err := readFileCapped(manifestPath)
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
// parent POM's groupId. An own groupId written in terms of the parent's
// coordinates (${project.parent.groupId}) is resolved; a self-reference would
// be circular and is kept verbatim, like any other expression.
func (doc *pomXML) effectiveGroupID() string {
	if groupID := strings.TrimSpace(doc.GroupID); groupID != "" {
		return coordinateReplacer(doc.parentCoordinates()).Replace(groupID)
	}
	return strings.TrimSpace(doc.ParentGroupID)
}

// parentCoordinates returns the parent POM's coordinates keyed by the model
// field Maven expressions use for them.
func (doc *pomXML) parentCoordinates() [][2]string {
	return [][2]string{
		{"parent.groupId", strings.TrimSpace(doc.ParentGroupID)},
		{"parent.artifactId", strings.TrimSpace(doc.ParentArtifactID)},
	}
}

// resolveBuiltinExpressions substitutes Maven's built-in project-coordinate
// expressions in a dependency coordinate with this POM's own values. Sibling
// modules are very commonly declared as
// <groupId>${project.groupId}</groupId>; without this the raw expression
// never equals any module's resolved groupId, and the sibling edge is
// silently dropped from the target's scope. User-defined <properties> are
// deliberately not interpolated: they may be inherited from a parent POM
// this package does not resolve, so a partial answer could be wrong (such
// text is compared verbatim instead -- see javaCoordinate).
func (doc *pomXML) resolveBuiltinExpressions(value string) string {
	if !strings.Contains(value, "${") {
		return value
	}
	fields := append([][2]string{
		{"groupId", doc.effectiveGroupID()},
		{"artifactId", strings.TrimSpace(doc.ArtifactID)},
	}, doc.parentCoordinates()...)
	return coordinateReplacer(fields).Replace(value)
}

// coordinateReplacer substitutes every spelling Maven 3 accepts for each
// {field, value} pair: ${project.<field>}, the deprecated Maven 2 alias
// ${pom.<field>}, and the deprecated unprefixed ${<field>}.
func coordinateReplacer(fields [][2]string) *strings.Replacer {
	pairs := make([]string, 0, len(fields)*6)
	for _, field := range fields {
		name, value := field[0], field[1]
		pairs = append(pairs, "${project."+name+"}", value, "${pom."+name+"}", value, "${"+name+"}", value)
	}
	return strings.NewReplacer(pairs...)
}

// newJavaProject builds a Project from a discovered pom.xml file, named by
// its artifactId, or its directory when it declares none.
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
// equals groupIDPrefix or starts with groupIDPrefix+"." (the SDK is
// io.modelcontextprotocol.sdk:mcp).
func javaGroupIDDependency(doc *pomXML, groupIDPrefix string) bool {
	for _, dep := range doc.Dependencies {
		groupID := strings.TrimSpace(doc.resolveBuiltinExpressions(dep.GroupID))
		if groupID == groupIDPrefix || strings.HasPrefix(groupID, groupIDPrefix+".") {
			return true
		}
	}
	return false
}

// resolveJavaLocalDeps fills in LocalDeps for every discovered Java project
// by matching each <dependency>'s groupId:artifactId against another
// discovered Java project's own effective coordinates. Maven has no
// path-based local dependency: a module dependency is written exactly like
// a Maven Central one, so a dependency is local when its coordinates name a
// module in this repository. As with Go module paths and Node package
// names, an unrelated published artifact with the same coordinates would be
// mistaken for the local module; telling them apart needs a registry
// lookup.
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
			coord := javaCoordinate(doc.resolveBuiltinExpressions(dep.GroupID), doc.resolveBuiltinExpressions(dep.ArtifactID))
			if coord == "" {
				continue
			}
			if target, ok := byCoordinate[coord]; ok && target != p {
				addLocalDep(p, target.Dir)
			}
		}
	}
}

// javaCoordinate returns groupId:artifactId, or "" when either is missing.
// Values are trimmed, as Maven itself does, since pretty-printed POMs may
// wrap them. An expression left unresolved is kept verbatim, so modules that
// all spell their coordinates with the same reactor-wide property (say
// ${revision.group}) still match each other -- accepting that two unrelated
// builds in one repository reusing a property name would match too.
func javaCoordinate(groupID, artifactID string) string {
	groupID, artifactID = strings.TrimSpace(groupID), strings.TrimSpace(artifactID)
	if groupID == "" || artifactID == "" {
		return ""
	}
	return groupID + ":" + artifactID
}
