package vigtool

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vigolium/vigolium/pkg/database"
)

// TestUpdateFindingProjectGuard locks the project-isolation fix: an
// update_finding tool scoped to project A cannot flip project B's finding by
// supplying its raw id, and the miss does not reveal that B's finding exists.
func TestUpdateFindingProjectGuard(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	ctx := context.Background()

	projA, projB := uuid.NewString(), uuid.NewString()
	f := &database.Finding{
		ProjectUUID: projB,
		ModuleID:    "mod",
		ModuleName:  "mod",
		Severity:    database.SeverityHigh,
		Confidence:  "firm",
		FindingHash: uuid.NewString(),
		Status:      database.StatusDraft,
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}

	toolA := NewUpdateFindingTool(&SessionsContext{Repo: repo, ProjectUUID: projA})
	res, err := toolA.Execute(ctx, map[string]any{"id": f.ID, "status": database.StatusFalsePositive}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content, "no finding with id") {
		t.Fatalf("cross-project update_finding should report not found, got: %+v", res)
	}
	if got, _ := repo.GetFindingByID(ctx, f.ID); got.Status != database.StatusDraft {
		t.Fatalf("project B finding status changed to %q", got.Status)
	}

	toolB := NewUpdateFindingTool(&SessionsContext{Repo: repo, ProjectUUID: projB})
	res, err = toolB.Execute(ctx, map[string]any{"id": f.ID, "status": database.StatusTriaged}, nil)
	if err != nil || res.IsError {
		t.Fatalf("in-project update_finding should succeed: %v %+v", err, res)
	}
	if got, _ := repo.GetFindingByID(ctx, f.ID); got.Status != database.StatusTriaged {
		t.Fatalf("status = %q, want triaged", got.Status)
	}
}
