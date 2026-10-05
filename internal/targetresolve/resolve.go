package targetresolve

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Resolve analyzes repoRoot and returns every discovered project, the subset
// of them selectable as scan targets, and any warnings about things found
// but not fully resolved (e.g. an uninitialized git submodule).
//
// Order matters internally:
//  1. discoverProjects (ecosystem manifests) and discoverLegacyPythonScripts
//     (manifest-less Python servers) both populate the same projects slice
//     before anything downstream runs.
//  2. applyWorkspaceRegistrySignals (Rush/Lerna/Nx/Turborepo/pnpm tagging and
//     Rush's defensive Name correction) runs next, before Node dependency
//     resolution, so a Name correction is visible to resolveNodeLocalDeps
//     (which keys workspace-protocol edges off Project.Name).
//  3. Workspace-local dependency edges (resolve*LocalDeps) and per-ecosystem
//     role classification (classifyRoles) are independent of each other and
//     can run in either order, but both must complete before
//     applyRegistryManifestSignals (the universal, language-agnostic Tier 1
//     signal, which overrides classifyRoles's conclusions where a
//     server.json exists).
//  4. applyRegistryManifestSignals must complete before promoteWrapperServers
//     (wrapper_classify.go) -- a Tier-1-confirmed server counts as valid
//     dependency-closure evidence for promoting a wrapper that depends on it.
//  5. promoteWrapperServers must complete before buildTargets -- buildTargets
//     (via demoteReachableFallbackServers) needs every project's final Role
//     already set, including any wrapper promotion, to compute fan-in
//     demotion correctly and to include the right set of projects in each
//     target's scan scope.
func Resolve(repoRoot string) (*Resolution, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}

	projects, err := discoverProjects(absRoot)
	if err != nil {
		return nil, err
	}

	legacyScripts, err := discoverLegacyPythonScripts(absRoot)
	if err != nil {
		return nil, err
	}
	projects = append(projects, legacyScripts...)

	workspaceWarnings := applyWorkspaceRegistrySignals(absRoot, projects)

	resolveGoLocalDeps(projects)
	resolveNodeLocalDeps(projects)
	resolvePythonLocalDeps(projects)
	resolveDotnetLocalDeps(absRoot, projects)
	resolveJavaLocalDeps(projects)
	resolveRustLocalDeps(projects)

	classifyRoles(projects)

	// Tier 1: an authoritative, language-agnostic server.json registry
	// manifest overrides whatever the per-ecosystem heuristics above
	// concluded, and can introduce a Project of its own for a directory with
	// no recognized ecosystem manifest at all (see registry_manifest.go).
	projects, err = applyRegistryManifestSignals(absRoot, projects)
	if err != nil {
		return nil, err
	}

	// Wrapper/composed-server promotion: a project with its own
	// executability evidence (bin entry or startup call) whose
	// workspace-local dependency closure reaches a confirmed server is
	// itself promoted to RoleMCPServer (see wrapper_classify.go).
	promoteWrapperServers(projects)

	components := assignIdentities(absRoot, projects)
	targets := buildTargets(projects)
	targets = mergeTargetsByComponent(targets)
	for _, target := range targets {
		target.ID = stableID("target", target.Project.ID)
		target.ComponentID = target.Project.ComponentID
		target.IncludedProjectIDs = make([]string, 0, len(target.Included))
		for _, project := range target.Included {
			target.IncludedProjectIDs = append(target.IncludedProjectIDs, project.ID)
		}
		sort.Strings(target.IncludedProjectIDs)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	warnings := append(detectSubmoduleWarnings(absRoot), workspaceWarnings...)
	inventory, excluded, inventoryErr := BuildInventoryForResolution(absRoot, projects, "", nil)
	if inventoryErr != nil {
		return nil, inventoryErr
	}
	for _, project := range projects {
		if project.OwnershipAmbiguous {
			warnings = append(warnings, fmt.Sprintf("ambiguous ownership for project %s", project.ID))
		}
	}

	return &Resolution{
		RepoRoot:   absRoot,
		Projects:   projects,
		Targets:    targets,
		Components: components,
		Inventory:  inventory,
		Excluded:   excluded,
		Warnings:   warnings,
	}, nil
}
