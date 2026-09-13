package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// mergeGlobFixtures runs the REAL --glob-db merge over a directory of fixtures
// and returns the scratch handle.
//
// It goes through openGlobDB rather than re-implementing the loop, because the
// thing under test IS openGlobDB's rowid-range bookkeeping: a test copy of that
// bookkeeping would keep passing if the production copy broke.
func mergeGlobFixtures(t *testing.T, dir string) *database.DB {
	t.Helper()
	t.Cleanup(resetDBCacheForTest)
	resetDBCacheForTest()

	db, err := openGlobDB(filepath.Join(dir, "*.sqlite"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}
	return db
}

// Record attribution is resolved from the per-file rowid ranges recorded at
// merge time, for the selected page only — not from a map holding every merged
// record. Each record must still report the file it came from.
func TestResolveGlobRecordSourcesAttributesEachFile(t *testing.T) {
	dir := t.TempDir()
	first := writeGlobSQLiteFixture(t, dir, "a.example", 3)
	second := writeGlobSQLiteFixture(t, dir, "b.example", 2)

	ctx := context.Background()
	db := mergeGlobFixtures(t, dir)

	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Order("url").Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(records) != 5 {
		t.Fatalf("merged %d records, want 5", len(records))
	}

	resolveGlobRecordSources(ctx, db, records)

	counts := map[string]int{}
	for _, rec := range records {
		file := globSourceForRecord(rec.UUID)
		if file == "" {
			t.Errorf("record %s has no source attribution", rec.UUID)
			continue
		}
		counts[file]++
	}
	if counts[first] != 3 || counts[second] != 2 {
		t.Fatalf("attribution = %d from first, %d from second; want 3 and 2", counts[first], counts[second])
	}
}

// Only the records handed in are resolved. The cache must not grow to the size
// of the merged corpus — that is the whole reason the eager map was removed.
func TestResolveGlobRecordSourcesOnlyCoversTheSelectedPage(t *testing.T) {
	dir := t.TempDir()
	src := writeGlobSQLiteFixture(t, dir, "a.example", 10)

	ctx := context.Background()
	db := mergeGlobFixtures(t, dir)

	var all []*database.HTTPRecord
	if err := db.NewSelect().Model(&all).Order("url").Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	page := all[:2]

	resolveGlobRecordSources(ctx, db, page)

	if len(globRecordFile) != 2 {
		t.Fatalf("cache holds %d entries after resolving a 2-record page, want 2", len(globRecordFile))
	}
	for _, rec := range page {
		if globSourceForRecord(rec.UUID) != src {
			t.Errorf("record %s not attributed to its source file", rec.UUID)
		}
	}
	// A record outside the page is simply unknown, not wrongly attributed.
	if got := globSourceForRecord(all[9].UUID); got != "" {
		t.Errorf("unresolved record reported source %q, want empty", got)
	}
}

// Resolving twice must not re-query, and must not lose or duplicate entries.
func TestResolveGlobRecordSourcesIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	_ = writeGlobSQLiteFixture(t, dir, "a.example", 4)

	ctx := context.Background()
	db := mergeGlobFixtures(t, dir)

	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	resolveGlobRecordSources(ctx, db, records)
	first := len(globRecordFile)
	resolveGlobRecordSources(ctx, db, records)
	if len(globRecordFile) != first {
		t.Fatalf("cache size changed on re-resolve: %d -> %d", first, len(globRecordFile))
	}
	if first != 4 {
		t.Fatalf("cache holds %d entries, want 4", first)
	}
}

// A read that is not a --glob-db merge has nothing to attribute, and must not
// touch the database to discover that.
func TestResolveGlobRecordSourcesNoOpWithoutGlob(t *testing.T) {
	prev := globDBSources
	t.Cleanup(func() { globDBSources = prev })
	globDBSources = nil

	resolveGlobRecordSources(context.Background(), nil, []*database.HTTPRecord{{UUID: "x"}})
	if globSourceForRecord("x") != "" {
		t.Fatal("a non-glob read must attribute nothing")
	}
}
