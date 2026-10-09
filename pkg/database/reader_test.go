package database

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// TestReaderPool_NotBlockedByWriter is the point of read intent: a writer
// holding BEGIN IMMEDIATE (a scan mid-batch) must not make a read command wait
// out busy_timeout. The writer holds its transaction for up to 3s; the reader's
// open, schema check and query must finish well inside 500ms.
func TestReaderPool_NotBlockedByWriter(t *testing.T) {
	path := currentFileDB(t)
	ctx := context.Background()

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	conn, err := w.Conn(ctx)
	if err != nil {
		t.Fatalf("writer conn: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO http_records (uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, status_code)
		 VALUES ('held-1', ?, 'https', 'example.test', 443, 'GET', '/', 'https://example.test/', 'HTTP/1.1', 'hash-1', 200)`,
		DefaultProjectUUID); err != nil {
		t.Fatalf("insert under held lock: %v", err)
	}
	released := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(released)
		select {
		case <-readerDone:
		case <-time.After(3 * time.Second):
		}
		_, _ = conn.ExecContext(ctx, "COMMIT")
	}()

	start := time.Now()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	cfg.ReadIntent = true
	r, err := NewDB(cfg)
	if err != nil {
		close(readerDone)
		t.Fatalf("open reader: %v", err)
	}
	checkErr := r.CheckSchema(ctx)
	var n int
	queryErr := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&n)
	_ = r.Close()
	elapsed := time.Since(start)
	close(readerDone)
	<-released

	if checkErr != nil || queryErr != nil {
		t.Fatalf("reader under a held write lock: check=%v query=%v", checkErr, queryErr)
	}
	if n != 0 {
		t.Errorf("reader saw %d rows of an uncommitted transaction, want 0", n)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("reader took %v under a held write lock, want < 500ms", elapsed)
	}
}

// TestReaderPool_LeavesDeleteModeFileUntouched: a read-intent open must not
// change the journal mode (the header's read/write version bytes), the main
// file's mtime, or leave sidecars behind — and must refuse writes outright.
func TestReaderPool_LeavesDeleteModeFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delete-mode.sqlite")
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	cfg.SQLite.JournalMode = "DELETE"
	w, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	if err := w.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	_ = w.Close()

	header := func() []byte {
		b, err := os.ReadFile(path)
		if err != nil || len(b) < 100 {
			t.Fatalf("read header: %v", err)
		}
		return append([]byte(nil), b[:100]...)
	}
	before := header()
	if before[18] != 1 || before[19] != 1 {
		t.Fatalf("fixture is not a rollback-journal file: write/read version = %d/%d", before[18], before[19])
	}
	stat, _ := os.Stat(path)
	mtime := stat.ModTime()
	time.Sleep(20 * time.Millisecond) // make any rewrite observable in mtime

	r := openReaderFile(t, path)
	ctx := context.Background()
	if err := r.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema: %v", err)
	}
	var n int
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if _, err := r.ExecContext(ctx, "DELETE FROM findings"); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "readonly") {
		t.Errorf("write through the read pool = %v, want a query_only refusal", err)
	}
	if err := r.CreateSchema(ctx); err != nil {
		t.Errorf("CreateSchema on a current store through the read pool = %v, want nil (a check)", err)
	}
	_ = r.Close()

	if after := header(); !bytes.Equal(before, after) {
		t.Errorf("reader changed the database header:\nbefore %v\nafter  %v", before, after)
	}
	if stat, _ := os.Stat(path); !stat.ModTime().Equal(mtime) {
		t.Errorf("reader changed the file mtime: %v -> %v", mtime, stat.ModTime())
	}
	for _, suffix := range sidecarSuffixes {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Errorf("reader left %s behind", suffix)
		}
	}
}

func TestReaderPool_RefusesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "missing.sqlite")
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	cfg.ReadIntent = true
	if db, err := NewDB(cfg); err == nil {
		_ = db.Close()
		t.Fatal("reader open of a missing file succeeded; it must not create one")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("reader open created the parent directory")
	}
}

func TestOpenReader_SecondPool(t *testing.T) {
	path := currentFileDB(t)
	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()

	r, separate, err := w.OpenReader()
	if err != nil || !separate || !r.IsReader() {
		t.Fatalf("OpenReader = %v, separate=%v, err=%v", r, separate, err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.ExecContext(context.Background(), "DELETE FROM findings"); err == nil {
		t.Error("second pool accepted a write")
	}

	// A reader asked for a reader hands itself back.
	same, separate, err := r.OpenReader()
	if err != nil || separate || same != r {
		t.Errorf("reader.OpenReader = %v, separate=%v, err=%v; want itself", same, separate, err)
	}
}
