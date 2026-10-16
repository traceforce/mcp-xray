package targetresolve

import (
	"fmt"
	"path/filepath"
	"slices"
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
	dirs := indexProjectDirs(projects)

	demoteReachableFallbackServers(projects, dirs)

	var targets []*Target
	for _, p := range projects {
		if p.Role != RoleMCPServer {
			continue
		}

		included := transitiveClosure(p, dirs)
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

		testDependents := includeTestDependents(p, includedSet, projects, dirs)
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
func includeTestDependents(primary *Project, alreadyIncluded map[*Project]bool, allProjects []*Project, dirs projectDirs) []*Project {
	var added []*Project
	for _, candidate := range allProjects {
		if alreadyIncluded[candidate] || !isTestShapedProject(candidate) {
			continue
		}

		closure := transitiveClosure(candidate, dirs)
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

// demoteReachableFallbackServers demotes to RoleSharedLibrary a project that
// is a server by source signal alone but that another server needs to run:
// a shared "core" library can hold a repository's only SDK construction
// call when every server calls a wrapper around it, which makes it look
// like a server. Only the dependencies a server runs with count
// (runtimeClosure): one pulled in for its tests is not its library. Nor is
// a server it is itself needed by: in a dependency cycle neither side is
// the other's library.
//
// Two kinds of server are never demoted: one confirmed by its own
// server.json (RoleConfirmedByManifest), and a launchable program
// (isLaunchable), which is a standalone server even when another server
// also depends on it -- @twilio-alpha/mcp depends on
// @twilio-alpha/openapi-mcp-server, which has a bin entry of its own.
func demoteReachableFallbackServers(projects []*Project, dirs projectDirs) {
	reaches := make(map[*Project]map[*Project]bool)
	for _, root := range projects {
		if root.Role != RoleMCPServer {
			continue
		}
		reaches[root] = make(map[*Project]bool)
		for _, reached := range runtimeClosure(root, dirs) {
			reaches[root][reached] = true
		}
	}
	reachedByAnotherServer := func(p *Project) bool {
		for root, reached := range reaches {
			if root != p && reached[p] && !reaches[p][root] {
				return true
			}
		}
		return false
	}

	for _, p := range projects {
		if p.Role == RoleMCPServer &&
			!p.RoleConfirmedByManifest &&
			reachedByAnotherServer(p) &&
			!isLaunchable(p, projects) {
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
					if reason.rank() > existing.rank() {
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

// transitiveClosure returns p plus every project reachable from p by
// following LocalDeps edges: all of p's own, development ones included (the
// code p is built and tested with), but only the runtime ones of the
// projects p depends on, whose development dependencies are never installed
// with them. Cycle-safe: a dependency cycle simply stops expanding once
// every reachable project has been visited once.
func transitiveClosure(p *Project, dirs projectDirs) []*Project {
	visited := make(map[*Project]bool)
	var order []*Project

	var visit func(cur *Project)
	visit = func(cur *Project) {
		if visited[cur] {
			return
		}
		visited[cur] = true
		order = append(order, cur)
		for _, depDir := range cur.LocalDeps {
			if cur != p && slices.Contains(cur.DevLocalDeps, depDir) {
				continue
			}
			if dep := dirs.dep(cur, depDir); dep != nil {
				visit(dep)
			}
		}
	}
	visit(p)

	return order
}

// projectDirs indexes projects by directory, which is how LocalDeps names
// them. Several projects can share a directory (a package.json beside a
// pyproject.toml), so it holds every one of them.
type projectDirs map[string][]*Project

func indexProjectDirs(projects []*Project) projectDirs {
	dirs := make(projectDirs, len(projects))
	for _, p := range projects {
		dir := filepath.Clean(p.Dir)
		dirs[dir] = append(dirs[dir], p)
	}
	return dirs
}

// dep returns the project that p's LocalDeps entry dir refers to: the one
// project in dir, or, when several share it, the one of p's own ecosystem,
// since every workspace resolver links a project only to projects of its
// own ecosystem (a file: dependency names a package.json, a Poetry path
// dependency a pyproject.toml). nil when there is none.
func (dirs projectDirs) dep(p *Project, dir string) *Project {
	candidates := dirs[filepath.Clean(dir)]
	if len(candidates) == 1 {
		return candidates[0]
	}
	for _, candidate := range candidates {
		if candidate.Ecosystem == p.Ecosystem {
			return candidate
		}
	}
	return nil
}
