package database

import (
	"context"
	"path/filepath"
	"testing"
)

// newUnseededFileDB is a database that has NOT been through SeedDefaults, so it
// has no search index yet — the state every database is in before the first
// seed, and the state a legacy file is in on upgrade.
func newUnseededFileDB(t *testing.T, name string) (*DB, string) {
	t.Helper()
	return openFileDB(t, filepath.Join(t.TempDir(), name), false)
}

// reopenFile opens the same SQLite file again, the way a second command would.
func reopenFile(t *testing.T, path string) *DB {
	t.Helper()
	db, _ := openFileDB(t, path, false)
	return db
}

func ftsMatchCount(t *testing.T, db *DB, term string) int64 {
	t.Helper()
	return scalarInt(t, db,
		`SELECT COUNT(*) FROM http_records_fts WHERE http_records_fts MATCH ?`, term)
}

// The search capability belongs to the database, not to whichever handle ran
// SeedDefaults. A read command reopening a seeded file must see the same index
// the seeding process created.
func TestHasFTSIsDiscoveredOnReopen(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "fts.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	if !db.HasFTS() {
		t.Fatal("seeding handle does not report FTS")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if reopened := reopenFile(t, path); !reopened.HasFTS() {
		t.Fatal("a reopened handle reports no FTS on a file that has the index")
	}
}

// A database with no index must report none, rather than reporting the last
// thing some handle happened to set.
func TestHasFTSFalseWithoutIndex(t *testing.T) {
	db, _ := newUnseededFileDB(t, "nofts.sqlite")
	if db.HasFTS() {
		t.Fatal("reported FTS with no index present")
	}
}

// An index table whose insert trigger is gone stops seeing new records. It must
// not be advertised as usable: a fast query that silently misses rows is worse
// than the slow one that does not.
func TestHasFTSFalseWhenTriggerMissing(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "notrig.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	mustExec(t, db, `DROP TRIGGER http_records_fts_ai`)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if reopenFile(t, path).HasFTS() {
		t.Fatal("an index with no insert trigger was reported as usable")
	}
}

// Replacing the legacy body-indexed table creates an EMPTY external-content
// index. Without the one-time rebuild, every record written before the upgrade
// is unsearchable forever — and the search reports no error.
func TestSeedDefaultsRebuildsIndexAfterLegacyMigration(t *testing.T) {
	ctx := context.Background()
	db, _ := newUnseededFileDB(t, "legacy.sqlite")

	// Stand up the legacy body-indexed shape, then add a record through it.
	mustExec(t, db, `CREATE VIRTUAL TABLE http_records_fts USING fts5(
		url, path, hostname, raw_request, raw_response,
		content=http_records, content_rowid=rowid)`)
	insertHTTPRecord(t, db, "legacy-rec", DefaultProjectUUID)

	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	if !db.HasFTS() {
		t.Fatal("FTS not available after legacy migration")
	}
	if got := ftsMatchCount(t, db, `"legacy-rec"*`); got != 1 {
		t.Fatalf("pre-existing record matches %d times after migration, want 1 — the index was not rebuilt", got)
	}
}

// A record that already existed before the index did must become searchable when
// the index is created, not only records written afterwards.
func TestSeedDefaultsIndexesPreExistingRecords(t *testing.T) {
	ctx := context.Background()
	db, _ := newUnseededFileDB(t, "prefill.sqlite")
	insertHTTPRecord(t, db, "older-rec", DefaultProjectUUID)

	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	if got := ftsMatchCount(t, db, `"older-rec"*`); got != 1 {
		t.Fatalf("record predating the index matches %d times, want 1", got)
	}
}

// url/path/hostname are mutable, and the index has to follow. Without the update
// trigger the old value kept matching and the new one never did.
func TestFTSFollowsMetadataUpdates(t *testing.T) {
	ctx := context.Background()
	db, _ := newFileDB(t, "update.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	insertHTTPRecord(t, db, "rec", DefaultProjectUUID)

	mustExec(t, db, `UPDATE http_records SET url = ?, path = ? WHERE uuid = 'rec'`,
		"https://example.com/relocated", "/relocated")

	if got := ftsMatchCount(t, db, `"relocated"*`); got != 1 {
		t.Errorf("the new url matches %d times, want 1", got)
	}
	if got := ftsMatchCount(t, db, `"rec"*`); got != 0 {
		t.Errorf("the replaced url still matches %d times, want 0", got)
	}
}

// Deleting a record must remove it from the index too.
func TestFTSFollowsDeletes(t *testing.T) {
	ctx := context.Background()
	db, _ := newFileDB(t, "delete.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	insertHTTPRecord(t, db, "doomed", DefaultProjectUUID)
	mustExec(t, db, `DELETE FROM http_records WHERE uuid = 'doomed'`)

	if got := ftsMatchCount(t, db, `"doomed"*`); got != 0 {
		t.Fatalf("a deleted record still matches %d times", got)
	}
}

// The MATCH argument is an FTS5 expression. A term carrying its syntax must be
// treated as data — a syntax error here would fail the whole listing, not just
// this predicate.
func TestFTSPrefixQueryEscapesExpressionSyntax(t *testing.T) {
	ctx := context.Background()
	db, _ := newFileDB(t, "escape.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	insertHTTPRecord(t, db, "rec", DefaultProjectUUID)

	for _, term := range []string{
		`admin"`, `a AND b`, `NEAR(x y)`, `foo:bar`, `-x`, `*`, `((`, `!!!`, `a OR b NOT c`,
	} {
		var n int64
		err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM http_records_fts WHERE http_records_fts MATCH ?`,
			ftsPrefixQuery(term)).Scan(&n)
		if err != nil {
			t.Errorf("term %q produced a MATCH error: %v", term, err)
		}
	}
}

// Same corpus, same term, two handles: one that seeded and one that reopened.
// The rows returned must not depend on which is asking.
func TestFuzzySearchIsIndependentOfOpenPath(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "fuzzy.sqlite")
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	// "superadmin" contains "admin" as a substring but not as a token, so the
	// FTS-only path used to miss it while the LIKE fallback found it.
	mustExec(t, db, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
		VALUES ('sa', ?, 'https', 'example.com', 443, 'GET', '/superadmin', 'https://example.com/superadmin', 'HTTP/1.1', 'rh-sa')`,
		DefaultProjectUUID)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	count := func(t *testing.T, handle *DB) int {
		t.Helper()
		recs, err := NewQueryBuilder(handle, QueryFilters{FuzzyTerm: "admin"}).Execute(ctx)
		if err != nil {
			t.Fatalf("fuzzy query: %v", err)
		}
		return len(recs)
	}

	withFTS := reopenFile(t, path)
	if !withFTS.HasFTS() {
		t.Fatal("reopened handle should have discovered the index")
	}
	got := count(t, withFTS)

	// Force the fallback by making the index undiscoverable to a fresh handle.
	mustExec(t, withFTS, `DROP TRIGGER http_records_fts_ai`)
	if err := withFTS.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	withoutFTS := reopenFile(t, path)
	if withoutFTS.HasFTS() {
		t.Fatal("handle should have fallen back")
	}
	want := count(t, withoutFTS)

	if got != want {
		t.Fatalf("--fuzzy admin returned %d rows with the index and %d without it", got, want)
	}
	if got != 1 {
		t.Fatalf("--fuzzy admin returned %d rows, want 1 (/superadmin is a substring match)", got)
	}
}
