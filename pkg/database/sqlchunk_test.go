package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	_ "modernc.org/sqlite"
)

// maxSQLParams is a claim about the driver, so test it against the driver —
// through database/sql, which actually binds. A driver bump that moves the
// ceiling should fail here, not on someone's corpus.
func TestSQLParamCeilingIsWhereWeThinkItIs(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "params.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec("CREATE TABLE t (uuid TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}

	exec := func(n int) error {
		args := make([]any, n)
		ph := make([]string, n)
		for i := range args {
			args[i] = fmt.Sprint(i)
			ph[i] = "?"
		}
		_, err := raw.Exec("DELETE FROM t WHERE uuid IN ("+strings.Join(ph, ",")+")", args...)
		return err
	}

	if err := exec(maxSQLParams); err != nil {
		t.Fatalf("%d bound parameters must be accepted, got: %v", maxSQLParams, err)
	}
	if err := exec(maxSQLParams + 1); err == nil {
		t.Fatalf("%d bound parameters unexpectedly accepted — maxSQLParams is stale", maxSQLParams+1)
	}
	if SQLChunkSize > maxSQLParams {
		t.Fatalf("SQLChunkSize (%d) exceeds the ceiling it is meant to stay under", SQLChunkSize)
	}
}

// Every query-builder call in this package assumes bun INTERPOLATES a list
// rather than binding it — that is why the chunk size is about SQL text length,
// and why the parameter ceiling above does not apply to those calls. If a bun
// upgrade starts binding, every unchunked bun.List in the tree becomes a hard
// "too many SQL variables" failure, so the assumption is pinned here.
func TestBunInterpolatesRatherThanBinds(t *testing.T) {
	db := newTestDB(t)
	got := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("uuid").
		Where("uuid IN (?)", bun.List([]string{"a", "b"})).
		String()
	if !strings.Contains(got, "'a', 'b'") {
		t.Fatalf("bun no longer interpolates list values — chunk sizes must be revisited against maxSQLParams.\nSQL: %s", got)
	}
}

// A list spanning several chunks must be answered in full, with the results of
// every chunk present — a lookup that returned only the first chunk's hits would
// read as "those records are gone".
func TestGetRecordsByUUIDsHandlesListsPastTheParamCeiling(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	// One real record at each end of a list long enough to span chunks, so a
	// result assembled from only one of them is visible. The absent uuids cost
	// nothing to ask about and keep the fixture cheap.
	const project = DefaultProjectUUID
	insertHTTPRecord(t, db, "rec-a", project)
	insertHTTPRecord(t, db, "rec-b", project)

	uuids := []string{"rec-a"}
	for i := range maxSQLParams + 100 {
		uuids = append(uuids, fmt.Sprintf("absent-%d", i))
	}
	uuids = append(uuids, "rec-b")

	records, err := repo.GetRecordsByUUIDs(ctx, uuids)
	if err != nil {
		t.Fatalf("GetRecordsByUUIDs over %d uuids: %v", len(uuids), err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	existing, err := repo.ExistingRecordUUIDs(ctx, project, uuids)
	if err != nil {
		t.Fatalf("ExistingRecordUUIDs over %d uuids: %v", len(uuids), err)
	}
	if len(existing) != 2 {
		t.Fatalf("ExistingRecordUUIDs returned %d, want 2", len(existing))
	}
}

// Deleting one of several records a finding cites must not take the finding with
// it — the other records are still its evidence. The junction entry for the
// deleted record must go, so nothing dangles.
func TestDeleteRecordsKeepsFindingsWithSurvivingEvidence(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	const project = DefaultProjectUUID

	insertHTTPRecord(t, db, "doomed", project)
	insertHTTPRecord(t, db, "survivor", project)
	shared := insertFinding(t, db, project, "fh-shared", "doomed")
	mustExec(t, db, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, shared, "doomed")
	mustExec(t, db, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, shared, "survivor")

	// A second finding cites only the doomed record: it loses all its evidence
	// and must go.
	solo := insertFinding(t, db, project, "fh-solo", "doomed")
	mustExec(t, db, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, solo, "doomed")

	del := NewDeleteBuilder(db, QueryFilters{ProjectUUID: project, RecordUUIDs: []string{"doomed"}})
	n, err := del.DeleteRecords(ctx, false)
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d records, want 1", n)
	}

	if got := scalarInt(t, db, `SELECT COUNT(*) FROM findings WHERE id = ?`, shared); got != 1 {
		t.Error("a finding that still cites a surviving record was deleted")
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM findings WHERE id = ?`, solo); got != 0 {
		t.Error("a finding left with no evidence was kept")
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM finding_records WHERE record_uuid = 'doomed'`); got != 0 {
		t.Errorf("%d junction rows still point at the deleted record", got)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM finding_records WHERE finding_id = ?`, shared); got != 1 {
		t.Errorf("surviving finding has %d junction rows, want 1 (survivor only)", got)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM finding_records WHERE finding_id = ?`, solo); got != 0 {
		t.Error("junction rows outlived their deleted finding")
	}
}

// An evidence-less finding that this delete did not touch is not this command's
// business — audit and source-scan findings legitimately have no HTTP record.
func TestDeleteRecordsLeavesUnrelatedRecordlessFindings(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	const project = DefaultProjectUUID

	insertHTTPRecord(t, db, "doomed", project)
	audit := insertFinding(t, db, project, "fh-audit", "")

	del := NewDeleteBuilder(db, QueryFilters{ProjectUUID: project, RecordUUIDs: []string{"doomed"}})
	if _, err := del.DeleteRecords(ctx, false); err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM findings WHERE id = ?`, audit); got != 1 {
		t.Error("a finding unrelated to the deleted records was swept up")
	}
}
