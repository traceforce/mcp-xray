package targetresolve

import (
	"fmt"
	"path/filepath"
)

// buildTargets computes, for every RoleMCPServer project, the transitive
// closure of its workspace-local dependencies (graph edges recorded in
// Project.LocalDeps by the workspace_*.go resolvers), promotes any
// RoleUnrelated project reachable that way to RoleSharedLibrary, and returns
// one Target per server project.
//
// A project already classified RoleMCPClient (or RoleConsumerConfigOnly)
// that happens to be reachable from a server is left with that more specific
// role rather than being overwritten -- it is still included in the target's
// scan scope (Included is dependency-based, not role-filtered), but its
// label keeps the more informative classification. Similarly, if a server's
// LocalDeps happen to reach a *different* server project (one server
// literally depending on another's package -- unusual, but not prevented by
// anything upstream), that other server and everything it in turn depends on
// is pulled into the first target's Included set as-is; this is treated as
// correct rather than special-cased away, since excluding it could just as
// easily discard a real, needed dependency.
func buildTargets(projects []*Project) []*Target {
	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	demoteReachableFallbackServers(projects, byDir)

	var targets []*Target
	for _, p := range projects {
		if p.Role != RoleMCPServer {
			continue
		}

		included := transitiveClosure(p, byDir)
		includedSet := make(map[*Project]bool, len(included))
		reasons := make(map[string]InclusionReason, len(included))
		for _, dep := range included {
			includedSet[dep] = true
		}
		for _, dep := range included {
			if dep == p {
				reasons[filepath.Clean(dep.Dir)] = InclusionPrimary
				continue
			}
			if dep.Role == RoleUnrelated {
				dep.Role = RoleSharedLibrary
			}
			if dep.Role == RoleSharedLibrary {
				evCopy := make([]string, len(dep.Evidence), len(dep.Evidence)+1)
				copy(evCopy, dep.Evidence)
				dep.Evidence = append(evCopy, fmt.Sprintf("referenced as a workspace-local dependency by %s", p.Name))
			}
			reasons[filepath.Clean(dep.Dir)] = InclusionSharedDependency
		}

		testDependents := includeTestDependents(p, includedSet, projects, byDir)
		for _, dep := range testDependents {
			evCopy := make([]string, len(dep.Evidence), len(dep.Evidence)+1)
			copy(evCopy, dep.Evidence)
			dep.Evidence = append(evCopy, fmt.Sprintf("included as a test/tooling harness for %s (depends on it via a workspace-local reference)", p.Name))
			reasons[filepath.Clean(dep.Dir)] = InclusionTestDependent
		}
		included = append(included, testDependents...)

		targets = append(targets, &Target{
			Name:            p.Name,
			Project:         p,
			Included:        included,
			IncludedReasons: reasons,
		})
	}

	return targets
}

// includeTestDependents returns every test-shaped project (isTestShapedProject,
// signals.go) not already in alreadyIncluded whose own forward LocalDeps
// closure reaches primary specifically -- e.g. a .NET src/X/X.csproj +
// tests/X.Tests/X.Tests.csproj split, where the ProjectReference edge points
// from the test project to the real one, the reverse of every other edge
// this package follows elsewhere. Scoped to test-shaped projects only, never
// a blanket reverse-closure: an unrelated consumer of a shared component
// already in scope must never be pulled into a target it has nothing to do
// with -- only a project whose own purpose is to exercise this exact primary
// project qualifies. alreadyIncluded is mutated as a side effect so a second
// qualifying candidate never re-adds a dependency the first one already
// contributed.
//
// A single pass over allProjects is sufficient (unlike promoteWrapperServers'
// fixed-point loop): whether a project is test-shaped never changes, and
// "does candidate's closure reach primary" is purely graph-topological --
// neither depends on what this function has added so far.
func includeTestDependents(primary *Project, alreadyIncluded map[*Project]bool, allProjects []*Project, byDir map[string]*Project) []*Project {
	var added []*Project
	for _, candidate := range allProjects {
		if alreadyIncluded[candidate] || !isTestShapedProject(candidate) {
			continue
		}

		closure := transitiveClosure(candidate, byDir)
		reachesPrimary := false
		for _, reached := range closure {
			if reached == primary {
				reachesPrimary = true
				break
			}
		}
		if !reachesPrimary {
			continue
		}

		for _, dep := range closure {
			if !alreadyIncluded[dep] {
				alreadyIncluded[dep] = true
				added = append(added, dep)
			}
		}
	}
	return added
}

// demoteReachableFallbackServers resolves a real ambiguity: a project
// classified RoleMCPServer purely by a per-ecosystem source-signal heuristic
// (signals.go) -- not confirmed by its own server.json registry manifest,
// registry_manifest.go -- that is also reachable, via LocalDeps, from a
// *different* RoleMCPServer project is almost certainly shared
// infrastructure that other server depends on, not a standalone server of
// its own. This is a confirmed real case, not a hypothetical: a shared
// "core" library can genuinely contain the one real SDK construction call
// in a repo, if every actual server calls a wrapper around it rather than
// the SDK directly, making the library indistinguishable from a real server
// by source signal alone.
//
// A project with RoleConfirmedByManifest == true is never demoted: an
// authoritative, language-agnostic server.json is definitive regardless of
// what else depends on it, or what it depends on.
//
// A project with its own hasOwnEntrypointEvidence (wrapper_classify.go --
// a bin entry or a startup call in its own source) is also never demoted:
// once wrapper_classify.go's promoteWrapperServers can create a second,
// truly independent server that's also reachable from a first server (the
// real twilio-labs/mcp shape -- @twilio-alpha/mcp depends on
// @twilio-alpha/openapi-mcp-server, and the latter is *also* independently
// a real server via its own separate bin/entrypoint), this rule would
// otherwise incorrectly flatten the depended-upon one to
// RoleSharedLibrary even though it's a genuine standalone server.
func demoteReachableFallbackServers(projects []*Project, byDir map[string]*Project) {
	reachableFromAnotherServer := make(map[*Project]bool)

	for _, root := range projects {
		if root.Role != RoleMCPServer {
			continue
		}
		for _, reached := range transitiveClosure(root, byDir) {
			if reached != root {
				reachableFromAnotherServer[reached] = true
			}
		}
	}

	for _, p := range projects {
		if p.Role == RoleMCPServer &&
			!p.RoleConfirmedByManifest &&
			!hasOwnEntrypointEvidence(p, projects) &&
			reachableFromAnotherServer[p] {
			p.Role = RoleSharedLibrary
		}
	}
}

// mergeTargetsByComponent collapses targets that share the same ComponentID
// into a single target. Multiple RoleMCPServer projects inside the same
// ownership root (e.g. a .NET server and its VS Code extension, or nested
// manifests under the same server.json boundary) must produce one selectable
// target, not one per project. The primary project is chosen deterministically:
// manifest-confirmed first, then by stable project ID.
func mergeTargetsByComponent(targets []*Target) []*Target {
	type group struct {
		primary *Target
		others  []*Target
	}
	byComponent := make(map[string]*group)
	var order []string
	for _, t := range targets {
		cid := t.Project.ComponentID
		g := byComponent[cid]
		if g == nil {
			g = &group{}
			byComponent[cid] = g
			order = append(order, cid)
		}
		if g.primary == nil {
			g.primary = t
		} else {
			better := false
			if t.Project.RoleConfirmedByManifest && !g.primary.Project.RoleConfirmedByManifest {
				better = true
			} else if t.Project.RoleConfirmedByManifest == g.primary.Project.RoleConfirmedByManifest && t.Project.ID < g.primary.Project.ID {
				better = true
			}
			if better {
				g.others = append(g.others, g.primary)
				g.primary = t
			} else {
				g.others = append(g.others, t)
			}
		}
	}

	merged := make([]*Target, 0, len(byComponent))
	for _, cid := range order {
		g := byComponent[cid]
		if len(g.others) == 0 {
			merged = append(merged, g.primary)
			continue
		}
		primary := g.primary
		includedSet := make(map[*Project]bool, len(primary.Included))
		for _, p := range primary.Included {
			includedSet[p] = true
		}
		for _, other := range g.others {
			for _, p := range other.Included {
				if includedSet[p] {
					reason := other.IncludedReasons[filepath.Clean(p.Dir)]
					existing := primary.IncludedReasons[filepath.Clean(p.Dir)]
					if inclusionPriority(reason) > inclusionPriority(existing) {
						primary.IncludedReasons[filepath.Clean(p.Dir)] = reason
					}
					continue
				}
				includedSet[p] = true
				primary.Included = append(primary.Included, p)
				reason := other.IncludedReasons[filepath.Clean(p.Dir)]
				if reason == "" {
					reason = InclusionSharedDependency
				}
				primary.IncludedReasons[filepath.Clean(p.Dir)] = reason
			}
		}
		merged = append(merged, primary)
	}
	return merged
}

func inclusionPriority(r InclusionReason) int {
	switch r {
	case InclusionPrimary:
		return 3
	case InclusionSharedDependency:
		return 2
	case InclusionTestDependent:
		return 1
	default:
		return 0
	}
}

// transitiveClosure returns p plus every project reachable from p by
// following LocalDeps edges. Cycle-safe: a dependency cycle simply stops
// expanding once every reachable project has been visited once.
func transitiveClosure(p *Project, byDir map[string]*Project) []*Project {
	byID := make(map[string]*Project, len(byDir))
	for _, project := range byDir {
		if project.ID != "" {
			byID[project.ID] = project
		}
	}
	visited := make(map[*Project]bool)
	var order []*Project

	var visit func(cur *Project)
	visit = func(cur *Project) {
		if visited[cur] {
			return
		}
		visited[cur] = true
		order = append(order, cur)
		usedStableEdge := false
		if len(cur.LocalDepIDs) > 0 {
			for _, depID := range cur.LocalDepIDs {
				if dep := byID[depID]; dep != nil {
					usedStableEdge = true
					visit(dep)
				}
			}
		}
		if !usedStableEdge {
			for _, depDir := range cur.LocalDeps {
				if dep := byDir[filepath.Clean(depDir)]; dep != nil {
					visit(dep)
				}
			}
		}
	}
	visit(p)

	return order
}
