package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// saveFindingFull inserts a finding and returns its assigned ID.
func saveFindingFull(t *testing.T, repo *Repository, f *Finding) int64 {
	t.Helper()
	ctx := context.Background()
	if f.FindingHash == "" {
		f.FindingHash = uuid.NewString()
	}
	if f.ModuleID == "" {
		f.ModuleID = "mod"
	}
	if f.ModuleName == "" {
		f.ModuleName = "mod"
	}
	if f.Severity == "" {
		f.Severity = SeverityMedium
	}
	if f.Confidence == "" {
		f.Confidence = "firm"
	}
	if f.ProjectUUID == "" {
		f.ProjectUUID = DefaultProjectUUID
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}
	return f.ID
}

func TestFindingGettersAndListing(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "find.example.com", "/x", 200)

	id := saveFindingFull(t, repo, &Finding{
		HTTPRecordUUIDs: []string{recUUID},
		Severity:        SeverityHigh,
		URL:             "https://find.example.com/x",
	})

	got, err := repo.GetFindingByID(ctx, id)
	if err != nil {
		t.Fatalf("GetFindingByID: %v", err)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("severity = %q", got.Severity)
	}

	// Retained candidates share storage but must stay out of finding-oriented
	// repository helpers and default lists.
	saveFindingFull(t, repo, &Finding{
		HTTPRecordUUIDs: []string{recUUID},
		Severity:        SeverityHigh,
		RecordKind:      RecordKindCandidate,
		URL:             "https://find.example.com/x",
	})

	byRec, err := repo.GetFindingsByRecordUUID(ctx, recUUID)
	if err != nil {
		t.Fatalf("GetFindingsByRecordUUID: %v", err)
	}
	if len(byRec) != 1 {
		t.Errorf("GetFindingsByRecordUUID = %d, want 1", len(byRec))
	}

	// GetFindingsBySeverity (project-scoped).
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh})
	highs, err := repo.GetFindingsBySeverity(ctx, DefaultProjectUUID, SeverityHigh, 10)
	if err != nil {
		t.Fatalf("GetFindingsBySeverity: %v", err)
	}
	if len(highs) != 2 {
		t.Errorf("GetFindingsBySeverity(high) = %d, want 2", len(highs))
	}

	// ListFindings with count.
	list, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 || len(list) != 2 {
		t.Errorf("ListFindings total=%d len=%d, want 2/2", total, len(list))
	}
	candidates, candidateTotal, err := repo.ListFindings(ctx, QueryFilters{
		ProjectUUID: DefaultProjectUUID,
		RecordKinds: []string{RecordKindCandidate},
	})
	if err != nil {
		t.Fatalf("ListFindings(candidates): %v", err)
	}
	if candidateTotal != 1 || len(candidates) != 1 {
		t.Errorf("candidate total=%d len=%d, want 1/1", candidateTotal, len(candidates))
	}
}

func TestFindingStatusValidationAndUpdates(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if !IsValidFindingStatus(StatusTriaged) || IsValidFindingStatus("bogus") {
		t.Error("IsValidFindingStatus wrong")
	}
	if !IsValidFindingSeverity(SeverityCritical) || IsValidFindingSeverity("bogus") {
		t.Error("IsValidFindingSeverity wrong")
	}

	id := saveFindingFull(t, repo, &Finding{Status: StatusDraft, Severity: SeverityLow})

	// UpdateFindingStatusScoped (unscoped form: scoping off).
	if err := repo.UpdateFindingStatusScoped(ctx, "", id, StatusTriaged); err != nil {
		t.Fatalf("UpdateFindingStatusScoped: %v", err)
	}
	got, _ := repo.GetFindingByID(ctx, id)
	if got.Status != StatusTriaged {
		t.Errorf("status = %q, want triaged", got.Status)
	}

	// Invalid status rejected; missing row → ErrNoRows.
	if err := repo.UpdateFindingStatusScoped(ctx, "", id, "bogus"); err == nil {
		t.Error("UpdateFindingStatusScoped(bogus) should error")
	}
	if err := repo.UpdateFindingStatusScoped(ctx, "", 999999, StatusFixed); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateFindingStatusScoped on missing row = %v, want sql.ErrNoRows", err)
	}

	// UpdateFindingSeverity.
	if err := repo.UpdateFindingSeverity(ctx, id, SeverityCritical); err != nil {
		t.Fatalf("UpdateFindingSeverity: %v", err)
	}
	if err := repo.UpdateFindingSeverity(ctx, id, "bogus"); err == nil {
		t.Error("UpdateFindingSeverity(bogus) should error")
	}

	// UpdateFindingTriage sets severity + description atomically.
	if err := repo.UpdateFindingTriage(ctx, DefaultProjectUUID, id, SeverityLow, "false positive: static asset"); err != nil {
		t.Fatalf("UpdateFindingTriage: %v", err)
	}
	got, _ = repo.GetFindingByID(ctx, id)
	if got.Severity != SeverityLow || got.Description == "" {
		t.Errorf("UpdateFindingTriage wrong: sev=%q desc=%q", got.Severity, got.Description)
	}
	if err := repo.UpdateFindingTriage(ctx, "", id, "bogus", "x"); err == nil {
		t.Error("UpdateFindingTriage(bogus) should error")
	}
}

func TestUpdateFindingStatusByHash(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	hash := uuid.NewString()
	agUUID := uuid.NewString()
	saveFindingFull(t, repo, &Finding{
		FindingHash:     hash,
		AgenticScanUUID: agUUID,
		Status:          StatusDraft,
	})

	n, err := repo.UpdateFindingStatusByHash(ctx, "", agUUID, hash, StatusFalsePositive)
	if err != nil {
		t.Fatalf("UpdateFindingStatusByHash: %v", err)
	}
	if n != 1 {
		t.Errorf("rows updated = %d, want 1", n)
	}

	// Invalid args.
	if _, err := repo.UpdateFindingStatusByHash(ctx, "", agUUID, hash, "bogus"); err == nil {
		t.Error("invalid status should error")
	}
	if _, err := repo.UpdateFindingStatusByHash(ctx, "", agUUID, "", StatusFixed); err == nil {
		t.Error("empty hash should error")
	}
}

// TestFindingStatusWritesAreProjectScoped locks the project-isolation fix: a
// writer scoped to project A cannot flip project B's finding by raw id or by a
// finding_hash both projects share.
func TestFindingStatusWritesAreProjectScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projA, projB := uuid.NewString(), uuid.NewString()
	sharedHash := uuid.NewString()
	idA := saveFindingFull(t, repo, &Finding{ProjectUUID: projA, FindingHash: sharedHash, Status: StatusDraft, Severity: SeverityHigh})
	idB := saveFindingFull(t, repo, &Finding{ProjectUUID: projB, FindingHash: sharedHash, Status: StatusDraft, Severity: SeverityHigh})

	// By id: B's finding is invisible to an A-scoped write.
	if err := repo.UpdateFindingStatusScoped(ctx, projA, idB, StatusFalsePositive); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-project status write = %v, want sql.ErrNoRows", err)
	}
	if err := repo.UpdateFindingTriage(ctx, projA, idB, SeverityInfo, "fp"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-project triage write = %v, want sql.ErrNoRows", err)
	}
	if got, _ := repo.GetFindingByID(ctx, idB); got.Status != StatusDraft || got.Severity != SeverityHigh {
		t.Fatalf("project B finding changed: status=%q severity=%q", got.Status, got.Severity)
	}
	// In-project write lands.
	if err := repo.UpdateFindingStatusScoped(ctx, projA, idA, StatusTriaged); err != nil {
		t.Fatalf("in-project status write: %v", err)
	}
	if got, _ := repo.GetFindingByID(ctx, idA); got.Status != StatusTriaged {
		t.Fatalf("project A status = %q, want triaged", got.Status)
	}

	// By hash: the swarm path touches only its own project's copy.
	n, err := repo.UpdateFindingStatusByHash(ctx, projB, "", sharedHash, StatusFixed)
	if err != nil || n != 1 {
		t.Fatalf("hash write = (%d, %v), want (1, nil)", n, err)
	}
	if got, _ := repo.GetFindingByID(ctx, idA); got.Status != StatusTriaged {
		t.Fatalf("project A finding changed by a project B hash write: %q", got.Status)
	}
}

func TestDeleteFinding(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "delfind.example.com", "/x", 200)
	id := saveFindingFull(t, repo, &Finding{HTTPRecordUUIDs: []string{recUUID}})

	if err := repo.DeleteFinding(ctx, id); err != nil {
		t.Fatalf("DeleteFinding: %v", err)
	}
	if _, err := repo.GetFindingByID(ctx, id); err == nil {
		t.Error("GetFindingByID should fail after delete")
	}
}

func TestFindingCountAggregations(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	agUUID := uuid.NewString()
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh, Confidence: "firm", AgenticScanUUID: agUUID, URL: "https://x.example.com/a"})
	saveFindingFull(t, repo, &Finding{Severity: SeverityHigh, Confidence: "tentative", AgenticScanUUID: agUUID, URL: "https://x.example.com/a"})
	saveFindingFull(t, repo, &Finding{Severity: SeverityLow, Confidence: "firm", URL: "https://x.example.com/b"})

	byAgentic, err := CountFindingsByAgenticScan(ctx, db, agUUID)
	if err != nil {
		t.Fatalf("CountFindingsByAgenticScan: %v", err)
	}
	if byAgentic[SeverityHigh] != 2 {
		t.Errorf("agentic high = %d, want 2", byAgentic[SeverityHigh])
	}
	// Empty UUID short-circuits.
	if m, err := CountFindingsByAgenticScan(ctx, db, ""); err != nil || len(m) != 0 {
		t.Errorf("CountFindingsByAgenticScan(empty) = %v, %v", m, err)
	}

	// CountFindingsByURL is run-scoped: only the two findings attributed to
	// agUUID (both on /a) are counted; the unattributed /b finding is excluded.
	byURL, err := CountFindingsByURL(ctx, db, agUUID)
	if err != nil {
		t.Fatalf("CountFindingsByURL: %v", err)
	}
	if byURL["https://x.example.com/a"] != 2 || byURL["https://x.example.com/b"] != 0 {
		t.Errorf("byURL = %v", byURL)
	}

	byConf, err := CountFindingsByConfidence(ctx, db, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("CountFindingsByConfidence: %v", err)
	}
	if byConf["firm"] != 2 || byConf["tentative"] != 1 {
		t.Errorf("byConfidence = %v", byConf)
	}
}
