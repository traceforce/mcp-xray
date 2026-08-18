package configscan

import (
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolAction is a classified capability of an MCP tool.
type ToolAction string

const (
	ToolActionRead    ToolAction = "read"
	ToolActionWrite   ToolAction = "write"
	ToolActionDelete  ToolAction = "delete"
	ToolActionUnknown ToolAction = "unknown"
)

// ClassifyToolActions inspects tool annotations, name, and description to
// determine whether the tool performs read, write, and/or delete actions.
//
// Annotation hints take priority: readOnlyHint adds "read" and blocks
// write/delete keyword inference unless destructiveHint is also true.
// When annotations are absent or incomplete, name/description keywords
// (shared with OAuth scope checks) fill the gaps. Returns ["unknown"]
// when no signal matches.
func ClassifyToolActions(tool *mcp.Tool) []ToolAction {
	if tool == nil {
		return []ToolAction{ToolActionUnknown}
	}

	readOnly := false
	destructive := false
	title := ""
	if tool.Annotations != nil {
		readOnly = tool.Annotations.ReadOnlyHint
		if tool.Annotations.DestructiveHint != nil {
			destructive = *tool.Annotations.DestructiveHint
		}
		title = tool.Annotations.Title
	}

	has := map[ToolAction]bool{}

	if readOnly {
		has[ToolActionRead] = true
	}
	if destructive {
		has[ToolActionDelete] = true
	}

	// Trust a read-only claim: skip write/delete keyword inference unless the
	// server also marks the tool destructive.
	runKeywords := !readOnly || destructive
	if runKeywords {
		text := strings.ToLower(strings.Join([]string{tool.Name, tool.Description, title}, " "))
		if containsAnyKeyword(deleteKeywords, text) {
			has[ToolActionDelete] = true
		}
		if containsAnyKeyword(writeKeywords, text) {
			has[ToolActionWrite] = true
		}
		if containsAnyKeyword(readKeywords, text) {
			has[ToolActionRead] = true
		}
	}

	if len(has) == 0 {
		return []ToolAction{ToolActionUnknown}
	}

	// Stable order: delete, write, read (unknown only when alone).
	order := []ToolAction{ToolActionDelete, ToolActionWrite, ToolActionRead}
	var actions []ToolAction
	for _, a := range order {
		if has[a] {
			actions = append(actions, a)
		}
	}
	return actions
}

// containsAnyKeyword reports whether text contains any keyword as a substring.
// Unlike checkStringSliceForKeywords it does not log matches.
func containsAnyKeyword(keywords []string, text string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

// actionStrings converts ToolAction values to plain strings for JSON output.
func actionStrings(actions []ToolAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = string(a)
	}
	return out
}
