package targetresolve

import (
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strings"
)

var msbuildRepoRoot = regexp.MustCompile(`(?i)\$\(RepoRoot\)`)

// csprojFile is the minimal shape of an SDK-style .csproj needed by this
// package: which other projects it references locally (ProjectReference)
// and which NuGet packages it depends on (PackageReference). Central
// package version management (Directory.Packages.props) is common in real
// repos, so PackageReference commonly has no Version attribute at all --
// this struct never reads one.
type csprojFile struct {
	XMLName    xml.Name          `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

type csprojItemGroup struct {
	ProjectReferences []csprojRef `xml:"ProjectReference"`
	PackageReferences []csprojRef `xml:"PackageReference"`
}

type csprojRef struct {
	Include string `xml:"Include,attr"`
}

// readCsproj centralizes the read+parse boilerplate, mirroring readGoMod.
func readCsproj(manifestPath string) (*csprojFile, error) {
	data, err := readFileCapped(manifestPath)
	if err != nil {
		return nil, err
	}
	var doc csprojFile
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// newDotnetProject builds a Project from a discovered .csproj file. Unlike
// Go/Node/Python, a .NET project's display name is a pure filesystem fact
// (the .csproj is conventionally named after the project itself, e.g.
// Fabric.Mcp.Server.csproj) rather than something declared inside the
// manifest, so this never needs to parse the file to construct a Project.
func newDotnetProject(manifestPath string) (*Project, error) {
	return &Project{
		Name:         strings.TrimSuffix(filepath.Base(manifestPath), ".csproj"),
		Dir:          filepath.Dir(manifestPath),
		Ecosystem:    "dotnet",
		ManifestPath: manifestPath,
	}, nil
}

// dotnetPackageReferencePrefix reports whether doc has a PackageReference
// whose Include equals prefix or starts with prefix+".", mirroring how the
// Go SDK's module path is prefix-matched in signals.go (e.g.
// "ModelContextProtocol" also matches "ModelContextProtocol.AspNetCore").
func dotnetPackageReferencePrefix(doc *csprojFile, prefix string) bool {
	for _, ig := range doc.ItemGroups {
		for _, ref := range ig.PackageReferences {
			if ref.Include == prefix || strings.HasPrefix(ref.Include, prefix+".") {
				return true
			}
		}
	}
	return false
}

// resolveDotnetLocalDeps fills in LocalDeps for every discovered .NET
// project by resolving each ProjectReference Include path, which has two
// complications:
//
//  1. MSBuild property expansion. $(RepoRoot) is a common convention
//     (defined once, at the repo root, in Directory.Build.props as
//     $(MSBuildThisFileDirectory), which ends in a separator, so
//     "$(RepoRoot)core\X\X.csproj" is the usual spelling) -- substituted
//     with repoRoot and a trailing separator here. Any
//     *other* unresolved $(...) token left in a path means "cannot resolve
//     this reference," and it is skipped rather than guessed at, the same
//     conservative posture isLocalFilesystemPath already uses for Go.
//  2. Wildcards. A ProjectReference Include can be a glob
//     (e.g. "$(RepoRoot)\tools\Fabric.*\src\*.csproj"), matched here,
//     after normalizing MSBuild's backslashes, against the projects
//     discovered in the repository -- never against the filesystem, where a
//     pattern like /*/*/*/*/*.csproj would walk the whole disk.
func resolveDotnetLocalDeps(repoRoot string, projects []*Project) {
	byDir := make(map[string]*Project)
	for _, p := range projects {
		if p.Ecosystem == "dotnet" {
			byDir[filepath.Clean(p.Dir)] = p
		}
	}
	if len(byDir) == 0 {
		return
	}

	for _, p := range projects {
		if p.Ecosystem != "dotnet" {
			continue
		}
		doc, err := readCsproj(p.ManifestPath)
		if err != nil {
			continue
		}
		for _, ig := range doc.ItemGroups {
			for _, ref := range ig.ProjectReferences {
				resolveDotnetProjectReference(p, ref.Include, repoRoot, byDir)
			}
		}
	}
}

// expandMSBuildPath substitutes the $(RepoRoot) convention and normalizes
// MSBuild's Windows-style backslashes to the host OS's separator. ok is
// false if a different, unhandled $(...) property remains, signaling the
// caller should give up on this reference rather than guess.
func expandMSBuildPath(raw string, repoRoot string) (string, bool) {
	expanded := msbuildRepoRoot.ReplaceAllLiteralString(raw, filepath.ToSlash(repoRoot)+"/")
	if strings.Contains(expanded, "$(") {
		return "", false
	}
	expanded = strings.ReplaceAll(expanded, "\\", "/")
	return filepath.Clean(filepath.FromSlash(expanded)), true
}

func resolveDotnetProjectReference(p *Project, rawInclude string, repoRoot string, byDir map[string]*Project) {
	expanded, ok := expandMSBuildPath(rawInclude, repoRoot)
	if !ok {
		return
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(p.Dir, expanded)
	}

	if strings.Contains(expanded, "*") {
		for _, dep := range byDir {
			if matched, _ := filepath.Match(expanded, dep.ManifestPath); matched {
				addDotnetProjectDep(p, dep.ManifestPath, byDir)
			}
		}
		return
	}

	addDotnetProjectDep(p, expanded, byDir)
}

func addDotnetProjectDep(p *Project, csprojPath string, byDir map[string]*Project) {
	targetDir := filepath.Clean(filepath.Dir(csprojPath))
	if dep, ok := byDir[targetDir]; ok && dep != p {
		addLocalDep(p, dep.Dir)
	}
}
