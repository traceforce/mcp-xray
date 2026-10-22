package libmcp

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Outcome statuses reported per server by dump-tools.
const (
	OutcomeOK           = "ok"
	OutcomeEmpty        = "empty"
	OutcomeAuthRequired = "auth_required"
	OutcomeUnlaunchable = "unlaunchable"
	OutcomeFailed       = "failed"
)

// maxToolPages bounds tools/list pagination so a server that never ends cannot run forever.
const maxToolPages = 100

// ServerOutcome is the per-server result of a dump-tools run.
type ServerOutcome struct {
	Server    string `json:"server"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	ToolCount int    `json:"tool_count"`
}

// ListAllTools follows nextCursor until the server stops paging. A repeated
// cursor or more than maxToolPages pages is an error, never a partial list.
func ListAllTools(ctx context.Context, session *mcp.ClientSession) ([]*mcp.Tool, error) {
	var tools []*mcp.Tool
	seen := map[string]bool{}
	params := &mcp.ListToolsParams{}
	for page := 1; ; page++ {
		if page > maxToolPages {
			return nil, fmt.Errorf("tools/list did not end after %d pages", maxToolPages)
		}
		res, err := session.ListTools(ctx, params)
		if err != nil {
			return nil, err
		}
		tools = append(tools, res.Tools...)
		if res.NextCursor == "" {
			return tools, nil
		}
		if seen[res.NextCursor] {
			return nil, fmt.Errorf("tools/list repeated cursor %q", res.NextCursor)
		}
		seen[res.NextCursor] = true
		params = &mcp.ListToolsParams{Cursor: res.NextCursor}
	}
}

// OutcomeForError maps a connect or tools/list error to an outcome status.
// A command that cannot be found or started (missing, not executable, wrong
// format) is unlaunchable; a server that answers 401 is auth_required.
func OutcomeForError(err error) string {
	var execErr *exec.Error
	var pathErr *fs.PathError
	var dcrErr *DCRUnauthorizedError
	switch {
	case errors.As(err, &execErr), errors.As(err, &pathErr) && pathErr.Op == "fork/exec":
		return OutcomeUnlaunchable
	case errors.As(err, &dcrErr), strings.Contains(err.Error(), "Unauthorized"):
		return OutcomeAuthRequired
	}
	return OutcomeFailed
}
