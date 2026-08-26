// Package targetresolve identifies the MCP server(s) inside a repository, tells
// them apart from clients/SDKs/shared libraries/consumer-only configs, and
// resolves the set of directories that must be scanned together to analyze
// one server accurately -- without recursing into unrelated sibling servers
// or unrelated parts of a larger monorepo.
//
// The design deliberately avoids per-vendor special-casing: everything below
// is expressed as (1) project discovery, (2) role classification, and (3)
// workspace-local dependency relationships. New repository layouts are meant
// to be supported by extending those three things, not by adding new branches
// to the resolution algorithm itself.
package targetresolve

// Role classifies what a discovered project actually is with respect to MCP.
type Role string

const (
	// RoleMCPServer is a project that implements/exposes an MCP server: it
	// depends on an MCP server SDK and contains server-construction code.
	RoleMCPServer Role = "mcp-server"

	// RoleMCPClient is a project that uses an MCP SDK only to connect to
	// servers (a client, a scanner, a host application) rather than exposing
	// one itself.
	RoleMCPClient Role = "mcp-client"

	// RoleSharedLibrary is a project with no MCP signal of its own that is
	// referenced, via a workspace-local dependency, by at least one
	// RoleMCPServer project.
	RoleSharedLibrary Role = "shared-library"

	// RoleConsumerConfigOnly is a project that merely configures/references
	// external MCP servers (an mcp.json-style config block) without any MCP
	// SDK dependency of its own. This must never be classified as a server --
	// it is the direct fix for the "MCP consumer false positive" pattern.
	RoleConsumerConfigOnly Role = "mcp-consumer-config-only"

	// RoleUnrelated is everything else: no MCP signal, not referenced by any
	// MCP server project.
	RoleUnrelated Role = "unrelated"

	// RoleRemoteReference is a directory that authoritatively describes an
	// MCP server (via a server.json with a non-empty "remotes" array) but
	// has no locally-buildable package ("packages" is empty/absent) and no
	// local server-construction evidence of its own -- there is nothing to
	// scan here. Distinct from RoleConsumerConfigOnly: a consumer-config-
	// only project CONSUMES/configures OTHER, external servers for its own
	// use (a client posture); a RoleRemoteReference project IS the subject
	// being described, just not locally, so it must not silently vanish
	// into RoleUnrelated either. buildTargets only creates a Target per
	// RoleMCPServer project, so a RoleRemoteReference project never becomes
	// a scan target while remaining visible in Resolution.Projects.
	RoleRemoteReference Role = "mcp-remote-reference"
)

// Project is one discovered unit of code identified by a single ecosystem
// manifest file (go.mod, package.json, pyproject.toml, ...).
type Project struct {
	// ID is a deterministic identity derived from the repository-relative
	// manifest (or directory for manifest-less projects), never from Name.
	ID string

	// Name is a human-readable display name: the manifest's own declared
	// name where available, falling back to the directory's base name.
	Name string

	// Dir is the absolute path to the project root (the directory containing
	// ManifestPath).
	Dir string

	// OwnershipRoot is the physical component boundary used for scanning. It
	// may be above Dir when a registry/component boundary owns sibling source,
	// tests, documentation, or deployment content.
	OwnershipRoot string

	// OwnershipEvidence explains why OwnershipRoot was selected. An empty
	// list means the conservative project-directory boundary was used.
	OwnershipEvidence  []string
	OwnershipAmbiguous bool

	// Ecosystem identifies which manifest family this project was
	// discovered from: "go", "node", "python", "dotnet", "java", or "rust".
	// "python-script" for a manifest-less legacy Python script discovered by
	// discover_python_script.go (no pyproject.toml/setup.py anywhere in its
	// directory tree). "unknown" for a project synthesized purely from a
	// server.json registry manifest with no recognized ecosystem manifest of
	// its own (registry_manifest.go).
	Ecosystem string

	// ManifestPath is the absolute path to the manifest file that defined
	// this project (go.mod, package.json, pyproject.toml).
	ManifestPath string

	// Role is the classification assigned by signals.go.
	Role Role

	// Evidence is a short human-readable trail of why Role was assigned --
	// surfaced in --list-targets output and useful when a classification
	// looks wrong and needs to be debugged.
	Evidence []string

	// LocalDeps is the set of other Project.Dir values this project depends
	// on via a workspace-local (path-based) dependency declaration, as
	// opposed to a registry dependency. Only workspace-local edges are
	// tracked here; registry dependencies are already handled by the
	// existing SCA scanner and are out of scope for this package.
	LocalDeps []string

	// LocalDepIDs is the stable-ID form of LocalDeps. LocalDeps remains for
	// compatibility with existing ecosystem adapters and callers; graph
	// planning uses this field when it is populated.
	LocalDepIDs []string

	// ComponentID identifies the logical ownership component containing this
	// project.
	ComponentID string

	// RoleConfirmedByManifest is true when Role == RoleMCPServer was
	// established by an authoritative, language-agnostic server.json
	// registry manifest (registry_manifest.go), as opposed to a per-ecosystem
	// source-code heuristic (signals.go). It exists to break a real ambiguity:
	// a shared library that happens to contain the one real SDK
	// construction call in a repo (because servers call a wrapper around it
	// rather than the SDK directly) looks exactly like a server by source
	// signal alone. graph.go uses this flag so that only a project with its
	// own official manifest is immune to being demoted to RoleSharedLibrary
	// when another confirmed server depends on it.
	RoleConfirmedByManifest bool

	// BinNames is the set of executable names this Node package declares via
	// package.json's own "bin" field: the package's own (scope-stripped)
	// name for the string form, or the object form's keys, sorted. Empty
	// for every non-Node project and for a Node project with no "bin"
	// field. This is auxiliary identity/executability evidence only -- no
	// require-following or build-output resolution is performed. It is
	// consulted by wrapper_classify.go's hasOwnEntrypointEvidence (a
	// project with its own bin entry has independent proof of being a
	// launchable entrypoint, not just a downstream dependency) and surfaced
	// by cmd/xray/target_cli.go for display.
	BinNames []string

	// WorkspaceSources records which higher-level workspace-management
	// tool(s) (rush/lerna/nx/turborepo/pnpm-workspace) recognize this
	// project as a member -- see workspace_registry.go. Stored in its own
	// field rather than appended to Evidence because classifyRoles
	// REPLACES (not appends to) Evidence, and this needs to survive that
	// assignment regardless of pipeline ordering.
	WorkspaceSources []string
}

// InclusionReason explains why a project appears in a Target's Included set.
type InclusionReason string

const (
	// InclusionPrimary is the target's own project.
	InclusionPrimary InclusionReason = "primary"

	// InclusionSharedDependency is a project reached by following the
	// primary project's own (forward) LocalDeps edges -- something the
	// target depends on.
	InclusionSharedDependency InclusionReason = "shared-dependency"

	// InclusionTestDependent is a test-shaped project (isTestShapedProject,
	// signals.go) whose LocalDeps reach the primary project in the reverse
	// direction -- something that depends on the target, such as a sibling
	// test/tooling project (e.g. .NET's src/X/X.csproj + tests/X.Tests
	// convention, where the ProjectReference edge points from the test
	// project to the real one). See graph.go's includeTestDependents.
	InclusionTestDependent InclusionReason = "test-dependent"
)

// Target is one selectable MCP server: its own project plus every project
// reachable from it via workspace-local dependencies (the shared components
// that must be included for an accurate scan).
type Target struct {
	// ID is a deterministic selectable identity. Name is display-only.
	ID string
	// Name mirrors Project.Name for display purposes.
	Name string

	// Project is the primary MCP-server project this target represents.
	Project *Project

	// Included is the full set of projects that must be scanned together for
	// this target: Project itself plus the transitive closure of its
	// workspace-local dependencies, plus any test-shaped project that
	// depends on Project (see InclusionTestDependent). Order is not
	// significant; ScanRoots (scope.go) is what callers should use to get a
	// deduplicated directory list.
	Included []*Project

	// IncludedReasons explains why each entry in Included is there, keyed by
	// filepath.Clean(Project.Dir). Purely additive diagnostic metadata --
	// never consulted by ScanRoots or any scanning logic itself.
	IncludedReasons map[string]InclusionReason

	// IncludedProjectIDs is the stable-ID form of Included.
	IncludedProjectIDs []string

	// ComponentID is the logical component represented by the primary project.
	ComponentID string
}

// Component is an ownership boundary. Multiple projects (including projects
// from different ecosystems) may share one component when they occupy the
// same evidence-backed ownership root.
type Component struct {
	ID         string
	Root       string
	ProjectIDs []string
	Evidence   []string
	Ambiguous  bool
}

// FileOwnership is the canonical ownership record for a file. Computed once
// during scan planning, it ensures every finding from the same file gets
// identical component IDs, target IDs, relation and context — regardless of
// which scan unit produced the finding.
type FileOwnership struct {
	ComponentIDs []string `json:"componentIds,omitempty"`
	TargetIDs    []string `json:"targetIds,omitempty"`
	Relation     string   `json:"relation"`
	Context      string   `json:"context"`
}

// TargetSummary is a per-target diagnostic record included in SARIF
// run-level properties so that every selected target remains visible even
// when it produces zero findings.
type TargetSummary struct {
	TargetID       string   `json:"targetId"`
	Name           string   `json:"name"`
	ProjectID      string   `json:"projectId"`
	ComponentID    string   `json:"componentId"`
	OwnershipRoot  string   `json:"ownershipRoot"`
	ScanUnitIDs    []string `json:"scanUnitIds"`
	RawFindings    int      `json:"rawFindings"`
	UniqueFindings int      `json:"uniqueFindings"`
}

// InventoryEntry is a deterministic repository inventory record. Path is
// always repository-relative POSIX syntax.
type InventoryEntry struct {
	Path         string   `json:"path"`
	ProjectIDs   []string `json:"projectIds,omitempty"`
	ComponentIDs []string `json:"componentIds,omitempty"`
	Manifest     bool     `json:"manifest,omitempty"`
	Lockfile     bool     `json:"lockfile,omitempty"`
	Excluded     bool     `json:"excluded,omitempty"`
	Ownership    string   `json:"ownership,omitempty"`
}

// Resolution is the complete result of analyzing a repository: every project
// found, the subset of them that are selectable targets, and any warnings
// about things the resolver could see but not fully act on (e.g. an
// uninitialized git submodule).
type Resolution struct {
	// RepoRoot is the absolute path the resolution was run against.
	RepoRoot string

	// Projects is every discovered project, of every role.
	Projects []*Project

	// Targets is the subset of Projects with Role == RoleMCPServer, each
	// resolved to its full Included set. This is what a caller presents to
	// the user for selection.
	Targets []*Target

	// Components is the deduplicated ownership model used by the scan planner.
	Components []*Component

	// Inventory is the deterministic repository inventory used for scope
	// diagnostics and residual planning.
	Inventory []InventoryEntry

	// Excluded contains deterministic repository-relative paths omitted from
	// inventory, primarily generated MCP X-Ray outputs.
	Excluded []string

	// Warnings are human-readable notices about things the resolver detected
	// but could not resolve automatically (e.g. "submodule at vendor/foo is
	// not checked out; its contents will not be scanned").
	Warnings []string
}
