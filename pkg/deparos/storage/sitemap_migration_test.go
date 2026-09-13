package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

// TestMigrateSchemaAddsColumnsToExistingStore is the old-database-meets-new-binary
// case for the discovery store.
//
// CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so a
// store written by an earlier vigolium keeps its original columns forever unless
// an explicit ALTER runs. Every read then fails on the missing column. This
// builds a deliberately stale `nodes` table — the pre-resp_duration_ms shape —
// and proves opening it brings it up to date rather than erroring.
func TestMigrateSchemaAddsColumnsToExistingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-sitemap.db")

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	ctx := context.Background()

	// The pre-migration shape: everything the old binary wrote, and nothing since.
	if _, err := db.ExecContext(ctx, `CREATE TABLE nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT NOT NULL,
		depth INTEGER,
		node_type INTEGER NOT NULL,
		req_method TEXT,
		resp_status INTEGER,
		resp_words INTEGER,
		resp_lines INTEGER,
		hash TEXT
	)`); err != nil {
		t.Fatalf("seed legacy table: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO nodes (url, node_type, resp_status) VALUES ('https://example.test/', 1, 200)`); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	if hasColumn(ctx, t, db, "nodes", "resp_duration_ms") {
		t.Fatal("precondition: the legacy table must not already have resp_duration_ms")
	}

	if err := migrateSchema(ctx, db); err != nil {
		t.Fatalf("migrateSchema on a legacy store: %v", err)
	}
	if !hasColumn(ctx, t, db, "nodes", "resp_duration_ms") {
		t.Error("resp_duration_ms was not added to an existing nodes table")
	}

	// Idempotent: reopening must not fail on the column it already added.
	if err := migrateSchema(ctx, db); err != nil {
		t.Fatalf("second migrateSchema: %v", err)
	}

	// The pre-existing row survives and reads back with an empty (unmeasured)
	// duration — never a fabricated one.
	var status int
	var duration sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT resp_status, resp_duration_ms FROM nodes WHERE url = 'https://example.test/'`,
	).Scan(&status, &duration); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want the pre-migration 200", status)
	}
	if duration.Valid {
		t.Errorf("duration = %d, want NULL — a legacy row was never timed", duration.Int64)
	}
	_ = db.Close()
}

func hasColumn(ctx context.Context, t *testing.T, db *bun.DB, table, column string) bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}
