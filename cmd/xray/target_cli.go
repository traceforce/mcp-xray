package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mcpxray/internal/targetresolve"

	"github.com/mattn/go-isatty"
)

// printDiscoveredTargets prints the numbered list of discovered MCP server
// targets, used by --list-targets and shown again before the interactive
// picker when a repo has more than one target. allProjects (Resolution.Projects)
// is used to print, per target, which other discovered projects in the repo
// are NOT part of that target's scan scope -- so nothing is left silently
// unaccounted for; pass nil to skip that section (there is no Resolution
// available yet). repoRoot, if non-empty, is used to print dependency-file
// paths relative to the repo instead of full absolute paths.
func printDiscoveredTargets(targets []*targetresolve.Target, allProjects []*targetresolve.Project, repoRoot string) {
	if len(targets) == 0 {
		fmt.Println("No MCP server targets discovered.")
		return
	}
	fmt.Println("Discovered MCP targets:")
	fmt.Println("  (repo-level files — CI, scripts, configs — are included with --include-repo-global)")
	for i, t := range targets {
		componentNote := ""
		if extra := len(t.Included) - 1; extra > 0 {
			componentNote = fmt.Sprintf(" (+%d shared component(s))", extra)
		}
		fmt.Printf("  %d. %s [%s]%s (id: %s)\n", i+1, t.Name, t.Project.Ecosystem, componentNote, t.ID)
		if len(t.Project.Evidence) > 0 {
			fmt.Printf("     evidence: %s\n", strings.Join(t.Project.Evidence, "; "))
		}
		if len(t.Project.BinNames) > 0 {
			fmt.Printf("     bin: %s\n", strings.Join(t.Project.BinNames, ", "))
		}
		if breakdown := inclusionReasonBreakdown(t); breakdown != "" {
			fmt.Printf("     scope: %s\n", breakdown)
		}
		if manifests := t.DependencyFiles(allProjects); len(manifests) > 0 {
			fmt.Printf("     dependency files (%d):\n", len(manifests))
			for _, m := range manifests {
				fmt.Printf("       %s\n", displayPath(m, repoRoot))
			}
		}
		if allProjects != nil {
			printNotIncludedSiblings(t, allProjects)
		}
	}
}

// displayPath renders path relative to repoRoot when possible (falls back to
// the original path on error, or when repoRoot is empty -- e.g. cross-drive
// on Windows, or the interactive-picker call site which has no Resolution
// yet). Purely cosmetic: never changes what is actually scanned.
func displayPath(path, repoRoot string) string {
	if repoRoot == "" {
		return path
	}
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// inclusionReasonBreakdown summarizes Target.IncludedReasons as e.g.
// "3 shared-dependency, 1 test-dependent" (the primary project itself is
// never counted -- it is implied by the target's own name/ecosystem line
// above). Returns "" when there is nothing beyond the primary to explain.
func inclusionReasonBreakdown(t *targetresolve.Target) string {
	counts := map[targetresolve.InclusionReason]int{}
	for _, reason := range t.IncludedReasons {
		counts[reason]++
	}
	var parts []string
	if n := counts[targetresolve.InclusionSharedDependency]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d shared-dependency", n))
	}
	if n := counts[targetresolve.InclusionTestDependent]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d test-dependent", n))
	}
	return strings.Join(parts, ", ")
}

// printNotIncludedSiblings prints, grouped by Role with a count per group,
// every project discovered elsewhere in the repo that is not part of t's
// scan scope -- the explicit, non-silent accounting of what a target-scoped
// scan leaves out, without pulling any of it into the scan itself (see the
// plan's "not scan-all" scope decision). Grouping by role keeps this
// scannable even in a large monorepo with hundreds of other projects,
// instead of one unbroken comma-separated line.
func printNotIncludedSiblings(t *targetresolve.Target, allProjects []*targetresolve.Project) {
	included := make(map[*targetresolve.Project]bool, len(t.Included))
	for _, p := range t.Included {
		included[p] = true
	}

	byRole := make(map[targetresolve.Role][]string)
	total := 0
	for _, p := range allProjects {
		if included[p] {
			continue
		}
		byRole[p.Role] = append(byRole[p.Role], p.Name)
		total++
	}
	if total == 0 {
		return
	}

	roles := make([]string, 0, len(byRole))
	for role := range byRole {
		roles = append(roles, string(role))
	}
	sort.Strings(roles)

	fmt.Printf("     not included in this scope (%d other project(s)):\n", total)
	for _, role := range roles {
		names := byRole[targetresolve.Role(role)]
		sort.Strings(names)
		fmt.Printf("       %s (%d): %s\n", role, len(names), strings.Join(names, ", "))
	}
}

// selectTarget resolves which target to scan when neither --target nor
// --target-id was given (a --target name is resolved by targetByName first):
//   - the single discovered target, automatically, if there is only one;
//   - an interactive numbered picker, if stdin is a terminal;
//   - otherwise a fail-fast error printing the discovered list and the exact
//     flag to pass for each target, so a CI/non-TTY run never guesses.
func selectTarget(targets []*targetresolve.Target, allProjects []*targetresolve.Project, repoRoot string) (*targetresolve.Target, error) {
	if len(targets) == 1 {
		return targets[0], nil
	}

	if isInteractiveTerminal() {
		return promptForTarget(targets, allProjects, repoRoot)
	}

	return nil, fmt.Errorf("multiple MCP targets discovered and no --target given; not prompting because stdin is not a terminal.\n%s", formatTargetListForError("Discovered MCP targets:", targets, repoRoot))
}

// targetByName returns the single target whose display name is exactly
// name. Names are display values, not identities -- two servers in one
// monorepo can both be named "server" -- so silently picking whichever one
// sorts first would scan the wrong server. An ambiguous name is therefore an
// error listing only the clashing targets, each with the --target-id that
// selects it unambiguously.
func targetByName(targets []*targetresolve.Target, repoRoot, name string) (*targetresolve.Target, error) {
	var matches []*targetresolve.Target
	for _, t := range targets {
		if t.Name == name {
			matches = append(matches, t)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no MCP target named %q was discovered.\n%s", name, formatTargetListForError("Discovered MCP targets:", targets, repoRoot))
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%d MCP targets are named %q; pass --target-id to choose one.\n%s", len(matches), name, formatTargetListForError(fmt.Sprintf("MCP targets named %q:", name), matches, repoRoot))
	}
}

// isInteractiveTerminal reports whether stdin is a terminal a user could
// respond to.
func isInteractiveTerminal() bool {
	return isTerminal(os.Stdin)
}

// isTerminal reports whether file is a terminal, covering both native
// terminals (isatty.IsTerminal) and mintty/Git-Bash on Windows
// (isatty.IsCygwinTerminal), which IsTerminal alone does not detect.
func isTerminal(file *os.File) bool {
	fd := file.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// printTargetHint points a user scanning the whole repository at
// --list-targets when it holds two or more MCP targets. Resolving them walks
// and reads the whole repository, so the hint is only for someone watching a
// terminal; a plain repo-scan in CI or a pipe costs what it did before.
func printTargetHint(repoPath string) {
	if !isTerminal(os.Stdout) {
		return
	}
	root, err := realDirectory(repoPath)
	if err != nil {
		return
	}
	if resolution, err := targetresolve.Resolve(root); err == nil && len(resolution.Targets) >= 2 {
		fmt.Printf("Detected %d MCP targets in this repository. To scan them individually instead of the whole repository, rerun with --list-targets.\n", len(resolution.Targets))
	}
}

func promptForTarget(targets []*targetresolve.Target, allProjects []*targetresolve.Project, repoRoot string) (*targetresolve.Target, error) {
	printDiscoveredTargets(targets, allProjects, repoRoot)
	fmt.Print("Select a target to scan (number): ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read target selection: %w", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(targets) {
		return nil, fmt.Errorf("invalid selection %q; expected a number from 1 to %d", strings.TrimSpace(line), len(targets))
	}

	return targets[choice-1], nil
}

// formatTargetListForError renders a target list under header for an error
// message: each target with its location and ecosystem (enough to tell
// same-named targets apart) and the exact flag that selects it. --target is
// only suggested for a name no other listed target shares; a shared name can
// only be selected with --target-id.
func formatTargetListForError(header string, targets []*targetresolve.Target, repoRoot string) string {
	nameCount := make(map[string]int, len(targets))
	for _, t := range targets {
		nameCount[t.Name]++
	}
	var sb strings.Builder
	sb.WriteString(header + "\n")
	for i, t := range targets {
		location := ""
		if t.Project != nil {
			location = fmt.Sprintf(" (%s, %s)", displayPath(t.Project.Dir, repoRoot), t.Project.Ecosystem)
		}
		if nameCount[t.Name] > 1 {
			sb.WriteString(fmt.Sprintf("  %d. %s%s -- pass --target-id %q\n", i+1, t.Name, location, t.ID))
		} else {
			sb.WriteString(fmt.Sprintf("  %d. %s%s -- pass --target %q or --target-id %q\n", i+1, t.Name, location, t.Name, t.ID))
		}
	}
	return sb.String()
}
