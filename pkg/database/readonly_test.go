package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sqliteSettings(path string, readOnly bool) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        path,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   -2000,
			ReadOnly:    readOnly,
		},
	}
}

// Opening a database read-only must leave the file byte-identical.
//
// The regression: openSQLite creates the parent directory, sets the
// journal_mode PRAGMA (a header rewrite) and runs wal_checkpoint(TRUNCATE) on
// open, so a plain read changed the source's SHA-256 and flipped it from
// `delete` to `wal`. For a `.sqlite` handed over as evidence that is the one
// thing a read must never do.
func TestReadOnlyOpenDoesNotModifySource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.sqlite")

	// Build a real database, then close it so nothing is mid-transaction.
	rw, err := NewDB(sqliteSettings(path, false))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := rw.CreateSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Drop WAL siblings so the comparison is against a settled single file.
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")

	before := sha256File(t, path)

	ro, err := NewDB(sqliteSettings(path, true))
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	// CreateSchema is a no-op on a read-only handle rather than a DDL write.
	if err := ro.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema on a read-only handle must be a no-op, got: %v", err)
	}
	var n int
	if err := ro.NewSelect().ColumnExpr("count(*)").Table("http_records").Scan(context.Background(), &n); err != nil {
		t.Fatalf("read-only query failed: %v", err)
	}
	if err := ro.Close(); err != nil {
		t.Fatalf("read-only close: %v", err)
	}

	if after := sha256File(t, path); after != before {
		t.Errorf("read-only open modified the source file\n before %s\n after  %s", before, after)
	}
}

// A read-only open of a path that does not exist is an error, never a freshly
// created empty database — a mistyped evidence path must not silently become a
// valid-looking empty store.
func TestReadOnlyOpenRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nested", "absent.sqlite")

	if _, err := NewDB(sqliteSettings(missing, true)); err == nil {
		t.Fatal("expected an error opening a missing file read-only")
	}
	if _, err := os.Stat(filepath.Dir(missing)); err == nil {
		t.Error("read-only open created the parent directory; it must not")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("read-only open created the database file; it must not")
	}
}
