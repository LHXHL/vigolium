package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// writableConfig points a DatabaseConfig at path with the ordinary read-write
// settings a scan uses. readOnlyConfig derives from it.
func writableConfig(path string) *config.DatabaseConfig {
	cfg := config.DefaultSettings().Database
	cfg.Enabled = true
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	return &cfg
}

// newSchemaDB opens a writable file-backed database with the schema created, and
// returns it with its path. File-backed rather than newTestDB's `:memory:`
// because these tests need a second connection to the same database.
func newSchemaDB(t *testing.T, cfg *config.DatabaseConfig) (*DB, string) {
	t.Helper()
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	// Cleanup, not defer: NewDB starts a WAL checkpointer goroutine for a
	// writable file-backed store, so a handle left open leaks it for the rest of
	// the run.
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(t.Context()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	return db, cfg.SQLite.Path
}

// tempSchemaDB is newSchemaDB at a fresh temp path with default settings.
func tempSchemaDB(t *testing.T) (*DB, string) {
	t.Helper()
	return newSchemaDB(t, writableConfig(filepath.Join(t.TempDir(), "test.sqlite")))
}

// insertScanLog writes one scan_logs row, the cheapest write these tests have.
func insertScanLog(t *testing.T, db *DB, scanUUID string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(),
		"INSERT INTO scan_logs (project_uuid, scan_uuid, level, phase, message, created_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
		DefaultProjectUUID, scanUUID, "info", "probe", "seeded"); err != nil {
		t.Fatalf("scan_logs insert (%s): %v", scanUUID, err)
	}
}

// seedWALFrames fills the WAL with frames a checkpoint has something to do with.
// Separate commits on purpose: one transaction would produce far fewer frames.
func seedWALFrames(t *testing.T, db *DB, rows int) {
	t.Helper()
	for i := 0; i < rows; i++ {
		insertScanLog(t, db, fmt.Sprintf("seed-%d", i))
	}
}

// holdTx opens a second connection to path and leaves a transaction open on it,
// standing in for another PROCESS holding the file — `serve`'s scan-on-receive
// poller, a `traffic` listing, or a concurrent scan, which is what the open path
// used to assume away.
//
// A read transaction pins the WAL so a TRUNCATE checkpoint cannot complete; a
// write transaction holds the lock any DDL needs. Returns a release func so a
// caller can drop the lock before its own handles close — a Close runs
// PRAGMA optimize, which is a write and would otherwise wait out the whole
// busy_timeout in teardown.
func holdTx(t *testing.T, path string, readOnly bool) (release func()) {
	t.Helper()
	dsn := path + "?_pragma=busy_timeout(1000)"
	if !readOnly {
		dsn += "&_txlock=immediate"
	}
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	tx, err := conn.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		t.Fatalf("begin holder tx (readOnly=%v): %v", readOnly, err)
	}
	// The statement is what actually acquires the lock: a read tx takes its
	// snapshot on first read, and _txlock=immediate takes the write lock at
	// BEGIN but the insert makes that explicit.
	if readOnly {
		var n int
		if err := tx.QueryRowContext(t.Context(), "SELECT count(*) FROM scan_logs").Scan(&n); err != nil {
			t.Fatalf("holder read: %v", err)
		}
	} else if _, err := tx.ExecContext(t.Context(),
		"INSERT INTO scan_logs (project_uuid, scan_uuid, level, phase, message, created_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
		DefaultProjectUUID, "holder", "info", "probe", "holding"); err != nil {
		t.Fatalf("holder write: %v", err)
	}

	var once bool
	release = func() {
		if !once {
			once = true
			_ = tx.Rollback()
		}
	}
	t.Cleanup(release)
	return release
}

// TestOpenDoesNotStallOnPinnedWALReader is the regression guard for the startup
// checkpoint. Opening a database that another reader holds must not wait out the
// busy_timeout: the open used to run wal_checkpoint(TRUNCATE), which blocked for
// the full 15s default and then reported busy=1 through a result row nobody read.
func TestOpenDoesNotStallOnPinnedWALReader(t *testing.T) {
	seed, path := tempSchemaDB(t)
	seedWALFrames(t, seed, 200)

	holdTx(t, path, true)

	// Append while the reader pins the older frames, so the WAL genuinely cannot
	// be reclaimed and a TRUNCATE has to wait rather than trivially succeeding.
	insertScanLog(t, seed, "after-pin")

	cfg := writableConfig(path)
	// Deliberately generous, and far above anything the open should need: the
	// assertion is that the open finishes in a small fraction of it, so a
	// reintroduced blocking checkpoint fails the test instead of merely slowing it.
	cfg.SQLite.BusyTimeout = 8000

	start := time.Now()
	contended, err := NewDB(cfg)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("contended open failed after %s: %v", elapsed, err)
	}
	t.Cleanup(func() { _ = contended.Close() })

	if limit := 2 * time.Second; elapsed > limit {
		t.Fatalf("open with a pinned WAL reader took %s (limit %s, busy_timeout %dms) — "+
			"the startup checkpoint is blocking on readers again",
			elapsed, limit, cfg.SQLite.BusyTimeout)
	}
}

// TestOpenSkipsCheckpointForNewFile covers the stateless path: a file with no
// leftover WAL has nothing to fold in, so the open must not checkpoint it. The
// observable difference is the sidecars — a checkpoint writes the -wal, so
// skipping it leaves the file the driver created untouched at zero length.
func TestOpenSkipsCheckpointForNewFile(t *testing.T) {
	db, path := tempSchemaDB(t)

	// A clean close folds the schema writes back and removes the sidecars, so the
	// reopen below sees exactly the "no leftover WAL" state stateless mode starts
	// from.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sidecarsPresent(path) {
		t.Skip("driver left sidecars after a clean close; nothing to assert")
	}

	reopened, err := NewDB(writableConfig(path))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	if _, err := reopened.ExecContext(t.Context(), "SELECT 1"); err != nil {
		t.Fatalf("reopened store unusable: %v", err)
	}
}

// TestCheckpointWALReportsBusy pins the behavior the old Exec-only call could
// not see: a checkpoint that cannot finish returns busy=1 and a nil error.
func TestCheckpointWALReportsBusy(t *testing.T) {
	db, path := tempSchemaDB(t)
	seedWALFrames(t, db, 200)

	// PASSIVE first, with nothing holding the file: it should complete cleanly.
	busy, err := checkpointWAL(t.Context(), db, "PASSIVE")
	if err != nil {
		t.Fatalf("uncontended PASSIVE checkpoint: %v", err)
	}
	if busy {
		t.Fatal("uncontended PASSIVE checkpoint reported busy")
	}

	holdTx(t, path, true)
	insertScanLog(t, db, "after-pin")

	// A TRUNCATE against a pinned reader is the silent case. It runs on its own
	// connection with a short busy_timeout so the test does not pay the stall it
	// is documenting.
	short, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(250)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open short-timeout handle: %v", err)
	}
	t.Cleanup(func() { _ = short.Close() })

	busy, err = checkpointWAL(t.Context(), short, "TRUNCATE")
	if err != nil {
		t.Fatalf("blocked TRUNCATE returned an error rather than a busy result: %v", err)
	}
	if !busy {
		t.Fatal("TRUNCATE against a pinned WAL reader did not report busy — " +
			"the busy result is what makes a blocking checkpoint observable")
	}
}
