package storage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempDBFiles lists sitemap-* entries anywhere under dir.
//
// The walk is not incidental: ephemeral sitemaps are allocated through
// internal/scratch, which nests them under a per-process directory rather than
// dropping them straight in the temp directory. What this guards is that Close
// removes them, not where they happen to sit.
func tempDBFiles(t *testing.T, dir string) []string {
	t.Helper()
	var matches []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // a directory racing cleanup is not this test's concern
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), "sitemap-") {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return matches
}

// TestSiteMapCloseRemovesOwnedTempDatabase is the regression guard for the temp
// database leak: CleanupFiles was a stub returning nil, so every discovery target
// stranded its sitemap-*.db (plus WAL sidecars) in the temp directory forever.
func TestSiteMapCloseRemovesOwnedTempDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	cfg := DefaultConfig()
	cfg.TargetURL = "https://example.test"
	cfg.SessionName = "cleanup-test"

	sm, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("NewSiteMap: %v", err)
	}
	if sm.tempPath == "" {
		t.Fatal("expected an ephemeral temp database")
	}
	if !sm.ephemeral {
		t.Error("ephemeral flag should be true for a temp database (it was computed after FilePath was overwritten)")
	}
	if files := tempDBFiles(t, dir); len(files) == 0 {
		t.Fatalf("expected the temp database to exist before Close")
	}

	if err := sm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if files := tempDBFiles(t, dir); len(files) != 0 {
		t.Errorf("Close left %d temp file(s) behind: %v", len(files), files)
	}
}

// TestNewSiteMapDoesNotMutateCallerConfig pins the ownership copy: allocating the
// temp database must not rewrite the caller's FilePath, or a second call on the
// same config silently reuses the first target's database.
func TestNewSiteMapDoesNotMutateCallerConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	cfg := DefaultConfig()
	cfg.TargetURL = "https://example.test"

	first, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("NewSiteMap #1: %v", err)
	}
	defer func() { _ = first.Close() }()

	if cfg.Database.FilePath != "" {
		t.Fatalf("caller config was mutated: FilePath = %q, want empty", cfg.Database.FilePath)
	}

	second, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("NewSiteMap #2: %v", err)
	}
	defer func() { _ = second.Close() }()

	if second.tempPath == first.tempPath {
		t.Errorf("second sitemap reused the first's database (%s)", first.tempPath)
	}
}

// TestCleanupFilesRemovesWALSidecars covers the sidecars WAL mode leaves beside
// the database, and the not-exist tolerance.
func TestCleanupFilesRemovesWALSidecars(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x.db")
	for _, p := range []string{base, base + "-wal", base + "-shm"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	d := &SQLiteDriver{}
	if err := d.CleanupFiles(base); err != nil {
		t.Fatalf("CleanupFiles: %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "x.db*")); len(files) != 0 {
		t.Errorf("left behind: %v", files)
	}
	// Already gone is not an error.
	if err := d.CleanupFiles(base); err != nil {
		t.Errorf("second CleanupFiles should be a no-op, got %v", err)
	}
	// An empty path is a no-op, never a cwd delete.
	if err := d.CleanupFiles(""); err != nil {
		t.Errorf("empty path should be a no-op, got %v", err)
	}
}
