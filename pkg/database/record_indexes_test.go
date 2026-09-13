package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// newDeferredIndexDB opens a file-backed database with record-index creation
// deferred, before any schema exists.
func newDeferredIndexDB(t *testing.T) *DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "deferred.sqlite")
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.DeferRecordIndexes()
	return db
}

func recordIndexCount(t *testing.T, db *DB) int64 {
	t.Helper()
	return scalarInt(t, db,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='http_records' AND name LIKE 'idx_%'`)
}

// A persistent store is written to continuously — there is no "after the load"
// in which to build its indexes — so it must have them from CreateSchema.
func TestCreateSchemaBuildsRecordIndexesByDefault(t *testing.T) {
	db, _ := newFileDB(t, "indexed.sqlite")
	if got := recordIndexCount(t, db); got != int64(len(recordSecondaryIndexes)) {
		t.Fatalf("built %d record indexes, want %d", got, len(recordSecondaryIndexes))
	}
}

// A deferring store loads against the primary key alone, then builds the read
// indexes once over the finished table.
func TestDeferRecordIndexesPostponesThemUntilAsked(t *testing.T) {
	ctx := context.Background()
	// Opened without CreateSchema so the defer can be armed first — the flag is
	// only consulted while the schema is being built.
	db := newDeferredIndexDB(t)
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	if got := recordIndexCount(t, db); got != 0 {
		t.Fatalf("%d record indexes exist after a deferred CreateSchema, want 0", got)
	}

	// Rows land with no index maintenance...
	insertHTTPRecord(t, db, "rec", DefaultProjectUUID)

	// ...and the indexes are built over them afterwards.
	if err := db.CreateRecordIndexes(ctx); err != nil {
		t.Fatalf("CreateRecordIndexes: %v", err)
	}
	if got := recordIndexCount(t, db); got != int64(len(recordSecondaryIndexes)) {
		t.Fatalf("built %d record indexes, want %d", got, len(recordSecondaryIndexes))
	}

	// The deferred index must actually be usable, not merely present.
	var plan string
	if err := db.QueryRowContext(ctx,
		`EXPLAIN QUERY PLAN SELECT uuid FROM http_records WHERE project_uuid = ? AND hostname = ?`,
		DefaultProjectUUID, "example.com").Scan(new(int), new(int), new(int), &plan); err != nil {
		t.Fatalf("explain: %v", err)
	}
	if plan == "SCAN http_records" {
		t.Errorf("a scoped host lookup still scans after the indexes were built: %s", plan)
	}
}

// Building twice, or building on a store that never deferred, must be a no-op
// rather than an error — the glob path calls it unconditionally.
func TestCreateRecordIndexesIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db, _ := newFileDB(t, "idempotent.sqlite")
	for range 2 {
		if err := db.CreateRecordIndexes(ctx); err != nil {
			t.Fatalf("CreateRecordIndexes: %v", err)
		}
	}
	if got := recordIndexCount(t, db); got != int64(len(recordSecondaryIndexes)) {
		t.Fatalf("have %d record indexes, want %d", got, len(recordSecondaryIndexes))
	}
}
