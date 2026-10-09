package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestCreateSchema_VersionGuardGatesBackfill proves the schema-version guard: the
// O(rows) finding_records backfill runs on a legacy (version 0) database but is
// skipped once the database is stamped current, so an up-to-date database no
// longer re-scans every finding on each open.
func TestCreateSchema_VersionGuardGatesBackfill(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// A fresh database is stamped at the current version by CreateSchema.
	if v := db.schemaVersion(ctx); v != currentSchemaVersion {
		t.Fatalf("schema version after CreateSchema = %d, want %d", v, currentSchemaVersion)
	}

	// A finding written directly carries http_record_uuids JSON — the shape the
	// backfill reconstructs finding_records links from.
	f := &Finding{
		ProjectUUID:     DefaultProjectUUID,
		ModuleID:        "m",
		ModuleName:      "m",
		Severity:        "low",
		Confidence:      "firm",
		FindingHash:     uuid.New().String(),
		Status:          StatusTriaged,
		HTTPRecordUUIDs: []string{"rec-uuid-1"},
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}

	countLinks := func() int {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_records").Scan(&n); err != nil {
			t.Fatalf("count finding_records: %v", err)
		}
		return n
	}
	clearLinks := func() {
		if _, err := db.ExecContext(ctx, "DELETE FROM finding_records"); err != nil {
			t.Fatalf("clear finding_records: %v", err)
		}
	}

	// Legacy database (version 0): the backfill runs and reconstructs the link.
	clearLinks()
	forceSchemaVersion(t, db, 0)
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (legacy): %v", err)
	}
	if got := countLinks(); got != 1 {
		t.Fatalf("legacy backfill: finding_records = %d, want 1 (backfill must run on an out-of-date DB)", got)
	}

	// Current database: the version was re-stamped above; delete the link and
	// re-run — the backfill must now be skipped, so it stays gone.
	clearLinks()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (current): %v", err)
	}
	if got := countLinks(); got != 0 {
		t.Fatalf("current backfill should be skipped: finding_records = %d, want 0", got)
	}
}

// forceSchemaVersion rewrites the stored version directly, simulating a legacy
// database: setSchemaVersion itself never lowers it.
func forceSchemaVersion(t *testing.T, db *DB, v int) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), "UPDATE schema_meta SET version = ? WHERE id = 1", v); err != nil {
		t.Fatalf("force schema version: %v", err)
	}
}

// TestSetSchemaVersion_NeverLowers is the regression for the downgrade bug: an
// older binary (lower currentSchemaVersion) running CreateSchema against a
// database a newer binary already stamped must not rewrite the version down.
func TestSetSchemaVersion_NeverLowers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	newer := currentSchemaVersion + 5
	db.setSchemaVersion(ctx, newer)
	if v := db.schemaVersion(ctx); v != newer {
		t.Fatalf("raise: version = %d, want %d", v, newer)
	}

	// What an older binary does on open.
	db.setSchemaVersion(ctx, currentSchemaVersion)
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if v := db.schemaVersion(ctx); v != newer {
		t.Fatalf("older binary lowered schema version to %d, want %d", v, newer)
	}
}
