package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func saveStatusFinding(t *testing.T, repo *Repository, project, hash string) *Finding {
	t.Helper()
	f := &Finding{ProjectUUID: project, ModuleID: "m", ModuleName: "M", Severity: SeverityHigh,
		Confidence: "firm", FindingHash: hash}
	if err := repo.SaveFindingDirect(context.Background(), f); err != nil || f.ID == 0 {
		t.Fatalf("save %s: id=%d err=%v", hash, f.ID, err)
	}
	return f
}

// TestUpdateFindingStatusScoped_IDsAndHashes: ids and hash prefixes resolve in
// one write, a finding named twice is changed once, each change stamps the
// note/actor and appends one event, and an already-matching finding is left
// alone.
func TestUpdateFindingStatusScoped_IDsAndHashes(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	a := saveStatusFinding(t, repo, DefaultProjectUUID, "aaaaaaaaaaaa1111111111111111111111111111")
	b := saveStatusFinding(t, repo, DefaultProjectUUID, "bbbbbbbbbbbb2222222222222222222222222222")

	res, err := repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		IDs:    []int64{a.ID, 999999},
		Hashes: []string{"BBBBBBBBBBBB", a.FindingHash, "cccccccccccc"},
		Status: StatusFalsePositive, Note: "static asset", Actor: "alice",
	})
	if err != nil {
		t.Fatalf("UpdateFindingStatusScoped: %v", err)
	}
	if len(res.Changed) != 2 {
		t.Fatalf("changed = %+v, want a and b once each", res.Changed)
	}
	if res.Changed[0].ID != a.ID || res.Changed[0].From != StatusTriaged || res.Changed[0].To != StatusFalsePositive {
		t.Errorf("change[0] = %+v", res.Changed[0])
	}
	if strings.Join(res.NotFound, ",") != "999999,cccccccccccc" {
		t.Errorf("not_found = %v", res.NotFound)
	}

	got, err := repo.GetFindingByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFalsePositive || got.StatusNote != "static asset" || got.StatusActor != "alice" || got.StatusUpdatedAt == nil {
		t.Errorf("finding after mark: status=%q note=%q actor=%q at=%v", got.Status, got.StatusNote, got.StatusActor, got.StatusUpdatedAt)
	}
	events, err := repo.ListFindingStatusEvents(ctx, DefaultProjectUUID, a.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %d, %v", len(events), err)
	}
	if e := events[0]; e.FromStatus != StatusTriaged || e.ToStatus != StatusFalsePositive || e.Note != "static asset" || e.Actor != "alice" {
		t.Errorf("event = %+v", e)
	}

	// Same verdict again: unchanged, no new event, note untouched.
	res, err = repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		IDs: []int64{a.ID}, Status: StatusFalsePositive, Note: "other", Actor: "bob",
	})
	if err != nil || len(res.Changed) != 0 || len(res.Unchanged) != 1 {
		t.Fatalf("repeat mark = %+v, %v", res, err)
	}
	if events, _ := repo.ListFindingStatusEvents(ctx, "", a.ID); len(events) != 1 {
		t.Errorf("repeat mark wrote an event: %d", len(events))
	}

	// A new verdict without a note clears the old note.
	if err := repo.SetFindingStatus(ctx, DefaultProjectUUID, a.ID, StatusConfirmed, "", "carol"); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetFindingByID(ctx, a.ID)
	if got.Status != StatusConfirmed || got.StatusNote != "" || got.StatusActor != "carol" {
		t.Errorf("after confirmed: status=%q note=%q actor=%q", got.Status, got.StatusNote, got.StatusActor)
	}
	_ = b
}

// TestUpdateFindingStatusScoped_ProjectIsolation: an id or hash from another
// project is not found, and the other project's finding is untouched.
func TestUpdateFindingStatusScoped_ProjectIsolation(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	const projB = "11111111-2222-3333-4444-555555555555"
	hash := "dddddddddddd3333333333333333333333333333"
	inA := saveStatusFinding(t, repo, DefaultProjectUUID, hash)
	inB := saveStatusFinding(t, repo, projB, hash) // same hash, other project

	res, err := repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		IDs: []int64{inB.ID}, Status: StatusFixed,
	})
	if err != nil || len(res.Changed) != 0 || len(res.NotFound) != 1 {
		t.Fatalf("cross-project id = %+v, %v", res, err)
	}
	if err := repo.SetFindingStatus(ctx, DefaultProjectUUID, inB.ID, StatusFixed, "", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("SetFindingStatus cross-project = %v, want sql.ErrNoRows", err)
	}

	// The hash names only the project's own finding, not the other project's.
	res, err = repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		Hashes: []string{hash[:12]}, Status: StatusFixed,
	})
	if err != nil || len(res.Changed) != 1 || res.Changed[0].ID != inA.ID {
		t.Fatalf("scoped hash = %+v, %v", res, err)
	}
	other, _ := repo.GetFindingByID(ctx, inB.ID)
	if other.Status == StatusFixed {
		t.Error("other project's finding was changed")
	}

	// Scoping off: the shared prefix is now ambiguous, and nothing is written.
	_, err = repo.UpdateFindingStatusScoped(ctx, "", FindingStatusUpdate{
		Hashes: []string{hash[:12]}, Status: StatusAcceptedRisk,
	})
	var amb *AmbiguousFindingHashError
	if !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Fatalf("unscoped shared prefix = %v, want ambiguity with 2 candidates", err)
	}
	other, _ = repo.GetFindingByID(ctx, inB.ID)
	if other.Status == StatusAcceptedRisk {
		t.Error("ambiguous write changed a finding")
	}
}

// TestUpdateFindingStatusScoped_AmbiguousPrefix: a prefix shared by two
// findings is refused with both listed, before anything is written.
func TestUpdateFindingStatusScoped_AmbiguousPrefix(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	a := saveStatusFinding(t, repo, DefaultProjectUUID, "eeeeeeeeeeee0000000000000000000000000001")
	saveStatusFinding(t, repo, DefaultProjectUUID, "eeeeeeeeeeee0000000000000000000000000002")

	_, err := repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		IDs: []int64{a.ID}, Hashes: []string{"eeeeeeeeeeee"}, Status: StatusFixed,
	})
	var amb *AmbiguousFindingHashError
	if !errors.As(err, &amb) {
		t.Fatalf("err = %v, want AmbiguousFindingHashError", err)
	}
	if !strings.Contains(err.Error(), "eeeeeeeeeeee0000000000000000000000000001") ||
		!strings.Contains(err.Error(), "eeeeeeeeeeee0000000000000000000000000002") {
		t.Errorf("error does not list candidates: %v", err)
	}
	got, _ := repo.GetFindingByID(ctx, a.ID)
	if got.Status == StatusFixed {
		t.Error("the id selector was written despite the ambiguous hash")
	}
}

func TestUpdateFindingStatusScoped_Validation(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if _, err := repo.UpdateFindingStatusScoped(ctx, "", FindingStatusUpdate{IDs: []int64{1}, Status: "bogus"}); err == nil {
		t.Error("invalid status accepted")
	}
	for _, h := range []string{"abc", "zzzzzzzzzzzzzz", "abcdef12345%"} {
		if _, err := repo.UpdateFindingStatusScoped(ctx, "", FindingStatusUpdate{Hashes: []string{h}, Status: StatusFixed}); err == nil {
			t.Errorf("hash selector %q accepted", h)
		}
	}
}
