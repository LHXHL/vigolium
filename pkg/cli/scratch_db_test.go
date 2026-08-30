package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// The whole point of the scratch database: it is a file, so a merge larger than
// RAM is paged by the OS instead of collapsing the process into swap.
func TestNewScratchDBIsFileBacked(t *testing.T) {
	db, err := newScratchDB("test")
	if err != nil {
		t.Fatalf("newScratchDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); removeScratchDB() })

	dir := scratchDBDir
	if dir == "" {
		t.Fatal("scratch directory was not recorded, so nothing would clean it up")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scratch dir: %v", err)
	}
	var found bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sqlite") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no .sqlite file in %s — the database is not file-backed", dir)
	}
}

// Regression: MaxOpenConns must NOT be pinned to 1. ":memory:" is forced to one
// connection because each connection there gets its own database — a constraint
// of in-memory SQLite, not something callers were written against. `export`
// streams rows while issuing further queries and deadlocks outright against a
// single connection, which is exactly what a scratch database is used for.
func TestScratchDBAllowsConcurrentConnections(t *testing.T) {
	db, err := newScratchDB("test")
	if err != nil {
		t.Fatalf("newScratchDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); removeScratchDB() })

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	for i := range 3 {
		if _, err := db.NewInsert().Model(&database.HTTPRecord{
			UUID: "rec-" + string(rune('a'+i)), ProjectUUID: "p", Scheme: "https",
			Hostname: "h.example", Port: 443, Method: "GET", Path: "/", URL: "https://h.example/",
			HTTPVersion: "HTTP/1.1", RequestHash: "rh-" + string(rune('a'+i)),
		}).Exec(ctx); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Hold a cursor open and run another query against the same database. With a
	// single connection this blocks until the test times out.
	rows, err := db.SQLDB().QueryContext(ctx, "SELECT uuid FROM http_records")
	if err != nil {
		t.Fatalf("open cursor: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		t.Fatal("expected at least one row")
	}

	done := make(chan error, 1)
	go func() {
		var n int
		done <- db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&n)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second query failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second query deadlocked while a cursor was open — MaxOpenConns is pinned too low")
	}
}

// A rollback must remain possible: mergeOnce wraps each file's copy in a
// transaction with a deferred Rollback, and rollback without a journal is
// undefined, so journal_mode must not be OFF.
func TestScratchDBKeepsAJournalSoRollbackWorks(t *testing.T) {
	db, err := newScratchDB("test")
	if err != nil {
		t.Fatalf("newScratchDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); removeScratchDB() })

	ctx := context.Background()
	var mode string
	if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if strings.EqualFold(mode, "off") {
		t.Fatal("journal_mode is OFF — a failed merge's rollback would corrupt the scratch database")
	}

	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	tx, err := db.SQLDB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
		VALUES ('x','p','https','h.example',443,'GET','/','https://h.example/','HTTP/1.1','rh')`); err != nil {
		t.Fatalf("insert in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var n int
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&n); err != nil {
		t.Fatalf("count after rollback: %v", err)
	}
	if n != 0 {
		t.Fatalf("rollback left %d row(s) behind", n)
	}
}

func TestRemoveScratchDBDeletesTheDirectory(t *testing.T) {
	db, err := newScratchDB("test")
	if err != nil {
		t.Fatalf("newScratchDB: %v", err)
	}
	dir := scratchDBDir
	_ = db.Close()

	removeScratchDB()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("scratch directory %s survived removeScratchDB (err=%v)", dir, err)
	}
	removeScratchDB() // must be safe twice
}

// A run killed mid-merge never reaches closeDatabaseOnExit, stranding a scratch
// database that on a real workload is tens of GB. The next run has to collect it.
func TestReapStaleScratchDBsRemovesAbandonedDirsOnly(t *testing.T) {
	root := os.TempDir()

	stale, err := os.MkdirTemp(root, scratchDBPrefix+"stale-")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := os.MkdirTemp(root, scratchDBPrefix+"fresh-")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := os.MkdirTemp(root, "not-vigolium-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(stale)
		_ = os.RemoveAll(fresh)
		_ = os.RemoveAll(unrelated)
	})

	// Back-date the stale one past the window, and the unrelated one too — a
	// directory that isn't ours must survive regardless of age.
	old := time.Now().Add(-scratchDBMaxAge - time.Hour)
	for _, dir := range []string{stale, unrelated} {
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
	}

	reapStaleScratchDBs()

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("an abandoned scratch dir survived the reaper (err=%v)", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a live scratch dir was reaped: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("the reaper deleted a directory that is not ours: %v", err)
	}
}

// Creating a second scratch database must not orphan the first one's path, or it
// leaks for the life of the process.
func TestNewScratchDBReplacesThePreviousOne(t *testing.T) {
	first, err := newScratchDB("test")
	if err != nil {
		t.Fatal(err)
	}
	firstDir := scratchDBDir
	_ = first.Close()

	second, err := newScratchDB("test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close(); removeScratchDB() })

	if _, err := os.Stat(firstDir); !os.IsNotExist(err) {
		t.Fatalf("the first scratch dir %s leaked (err=%v)", filepath.Base(firstDir), err)
	}
}
