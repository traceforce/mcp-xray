package configscan

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool { return &v }

func TestClassifyToolActions_ReadOnlyHint(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name: "API-get-self",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
			Title:        "Get User",
		},
	})
	require.Equal(t, []ToolAction{ToolActionRead}, actions)
}

func TestClassifyToolActions_DestructiveHintOnly(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "xyzzy",
		Description: "florb the quux",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(true),
		},
	})
	require.Equal(t, []ToolAction{ToolActionDelete}, actions)
}

func TestClassifyToolActions_NoAnnotationsDeleteVerb(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "cleanup",
		Description: "Delete records from the collection",
	})
	require.Contains(t, actions, ToolActionDelete)
}

func TestClassifyToolActions_NoAnnotationsWriteVerb(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "create_page",
		Description: "Create or update a page in the workspace",
	})
	require.Contains(t, actions, ToolActionWrite)
	require.NotContains(t, actions, ToolActionUnknown)
}

func TestClassifyToolActions_NoAnnotationsReadVerb(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "list_items",
		Description: "Get and list available resources",
	})
	require.Equal(t, []ToolAction{ToolActionRead}, actions)
}

func TestClassifyToolActions_EmptyUnknown(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "xyzzy",
		Description: "florb the quux",
	})
	require.Equal(t, []ToolAction{ToolActionUnknown}, actions)
}

func TestClassifyToolActions_NilToolUnknown(t *testing.T) {
	actions := ClassifyToolActions(nil)
	require.Equal(t, []ToolAction{ToolActionUnknown}, actions)
}

func TestClassifyToolActions_ReadOnlyTrustsAnnotationOverWriteVerb(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "export_and_write_report",
		Description: "Create and write a report file from exported data",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	})
	require.Equal(t, []ToolAction{ToolActionRead}, actions)
}

func TestClassifyToolActions_ReadOnlyPlusDestructiveAllowsKeywords(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "migrate",
		Description: "Create a new copy then delete the old record",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(true),
		},
	})
	require.Contains(t, actions, ToolActionRead)
	require.Contains(t, actions, ToolActionDelete)
	require.Contains(t, actions, ToolActionWrite)
}

func TestClassifyToolActions_StableOrder(t *testing.T) {
	actions := ClassifyToolActions(&mcp.Tool{
		Name:        "sync",
		Description: "Read existing data, update records, and delete stale entries",
	})
	require.Equal(t, []ToolAction{ToolActionDelete, ToolActionWrite, ToolActionRead}, actions)
}
