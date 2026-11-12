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
// The passes run in a fixed order:
//  1. discover every project (ecosystem manifests and manifest-less Python
//     scripts);
//  2. resolve workspace-local dependency edges and classify each project's
//     role from its own manifest and source;
//  3. apply server.json registry manifests, which override that
//     classification where present;
//  4. promote wrappers whose dependency closure reaches a confirmed server;
//  5. build targets, which needs every role final.
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

	resolveGoLocalDeps(projects)
	resolveNodeLocalDeps(projects)
	resolvePythonLocalDeps(absRoot, projects)
	resolveDotnetLocalDeps(absRoot, projects)
	resolveJavaLocalDeps(projects)
	resolveRustLocalDeps(absRoot, projects)

	classifyRoles(projects)

	projects, err = applyRegistryManifestSignals(absRoot, projects)
	if err != nil {
		return nil, err
	}

	promoteWrapperServers(projects)

	components := assignIdentities(absRoot, projects)
	markEmbeddedScripts(projects)
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
	warnings := detectSubmoduleWarnings(absRoot)
	inventory, excluded, inventoryErr := buildInventory(absRoot, projects)
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
