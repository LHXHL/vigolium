package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// oneColumnBehindDB returns a file-backed database in exactly the state an
// older vigolium leaves behind: the current schema minus one column that a
// later release added.
//
// Built by migrating a real database and then dropping the column, rather than
// by hand-writing a stale CREATE TABLE — a hand-written stub omits base columns
// too (sent_at, and the indexes that reference them), which fails for reasons
// that have nothing to do with the case under test. Forward migration itself is
// already covered by TestCreateSchema_UpgradeFromGenesisBaseline.
func oneColumnBehindDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "one-behind.sqlite")

	db := openDBFile(t, path, false)
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("build current schema: %v", err)
	}
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO http_records (uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, status_code)
		 VALUES ('legacy-1', ?, 'https', 'example.test', 443, 'GET', '/', 'https://example.test/', 'HTTP/1.1', 'hash-1', 200)`,
		DefaultProjectUUID); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	// The index on the column has to go first — SQLite refuses to drop a column
	// an index still references. CreateSchema rebuilds both on the next open,
	// which is precisely the migration under test.
	if _, err := db.ExecContext(context.Background(),
		"DROP INDEX IF EXISTS idx_records_project_surface_score"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := db.ExecContext(context.Background(),
		"ALTER TABLE http_records DROP COLUMN surface_score"); err != nil {
		t.Skipf("this SQLite build cannot DROP COLUMN, so the legacy state cannot be simulated: %v", err)
	}
	_ = db.Close()
	return path
}

func openDBFile(t *testing.T, path string, readOnly bool) *DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	cfg.SQLite.ReadOnly = readOnly
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("open (readOnly=%v): %v", readOnly, err)
	}
	return db
}

// TestCreateSchemaReadOnlyReportsOutdated pins the one case migration cannot
// fix: a read-only handle has no way to ALTER, so it must say so with a remedy
// instead of letting the caller's first SELECT fail on a missing column. That
// error used to reach the operator as a bare "no such column:
// r.surface_score" — a symptom with no fix attached.
func TestCreateSchemaReadOnlyReportsOutdated(t *testing.T) {
	path := oneColumnBehindDB(t)

	ro := openDBFile(t, path, true)
	err := ro.CreateSchema(context.Background())
	_ = ro.Close()
	if !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("read-only CreateSchema on a stale db = %v, want ErrSchemaOutdated", err)
	}
	// Naming the missing column is the point: "outdated" alone does not tell an
	// operator whether the file is one column or one release behind.
	if got := err.Error(); !strings.Contains(got, "surface_score") {
		t.Errorf("error %q does not name the missing column", got)
	}

	// A writable open migrates it, and the same read-only open is then clean —
	// the check must be a staleness report, not a permanent refusal.
	rw := openDBFile(t, path, false)
	migrateErr := rw.CreateSchema(context.Background())
	_ = rw.Close()
	if migrateErr != nil {
		t.Fatalf("migrate: %v", migrateErr)
	}

	ro2 := openDBFile(t, path, true)
	defer func() { _ = ro2.Close() }()
	if err := ro2.CreateSchema(context.Background()); err != nil {
		t.Errorf("read-only CreateSchema on a migrated db = %v, want nil", err)
	}

	// The pre-existing row survived the migration, and its new column reads as
	// the zero that means "never scored" rather than a fabricated value.
	var status, surface int
	if err := ro2.QueryRowContext(context.Background(),
		`SELECT status_code, surface_score FROM http_records WHERE uuid = 'legacy-1'`,
	).Scan(&status, &surface); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if status != 200 || surface != 0 {
		t.Errorf("row after migration: status=%d surface=%d, want 200 and 0", status, surface)
	}
}

// TestCreateSchemaReadOnlyAcceptsEmptyDatabase: a brand-new or empty file is not
// "outdated" — it has no tables at all, and every read of it correctly returns
// nothing. Refusing it would break reading a freshly created stateless export.
func TestCreateSchemaReadOnlyAcceptsEmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec("CREATE TABLE placeholder (id INTEGER)"); err != nil {
		t.Fatalf("touch file: %v", err)
	}
	_ = raw.Close()

	db := openDBFile(t, path, true)
	defer func() { _ = db.Close() }()
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Errorf("read-only CreateSchema on an empty database = %v, want nil", err)
	}
}
