package database

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// readOnlyConfig points a DatabaseConfig at path in read-only mode.
func readOnlyConfig(path string) *config.DatabaseConfig {
	cfg := writableConfig(path)
	cfg.SQLite.ReadOnly = true
	return cfg
}

// writeTestStore creates a real vigolium SQLite file at path and closes it, so
// the follow-up read-only open sees a normal on-disk store with no sidecars.
func writeTestStore(t *testing.T, path string) {
	t.Helper()
	db, err := NewDB(writableConfig(path))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.CreateSchema(t.Context()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestReadOnlyOpenLeavesNoSidecars is the point of --read-only: the flag is
// documented for evidence files, so a pass over one must leave the directory as
// it was found. Before this, mode=ro created a -shm and an empty -wal and left
// them there, while an ordinary read (which creates the same pair) checkpointed
// and removed them on close.
func TestReadOnlyOpenLeavesNoSidecars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.sqlite")
	writeTestStore(t, path)

	before := dirEntries(t, dir)
	if len(before) != 1 {
		t.Fatalf("fixture should be a lone file, found %v", before)
	}

	db, err := NewDB(readOnlyConfig(path))
	if err != nil {
		t.Fatalf("read-only NewDB: %v", err)
	}
	// Touch the store so the WAL index is genuinely brought up, not merely
	// opened; an open that never reads may not create the -shm at all.
	if _, err := db.NewSelect().Table("http_records").Count(t.Context()); err != nil {
		t.Fatalf("count: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if after := dirEntries(t, dir); len(after) != 1 {
		t.Errorf("read-only open left %v beside the evidence file; want just the database", after)
	}
}

// TestReadOnlyOpenKeepsPreexistingSidecars is the safety half. A -wal that was
// already there belongs to whoever wrote it — very possibly a live writer whose
// committed frames have not been checkpointed — and removing it would discard
// those transactions.
func TestReadOnlyOpenKeepsPreexistingSidecars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.sqlite")
	writeTestStore(t, path)

	// Stand in for another process's WAL: non-empty, so even the "ours" rule
	// would refuse it.
	walPath := path + "-wal"
	if err := os.WriteFile(walPath, []byte("pretend frames"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := NewDB(readOnlyConfig(path))
	if err != nil {
		t.Fatalf("read-only NewDB: %v", err)
	}
	_ = db.Close()

	if _, err := os.Stat(walPath); err != nil {
		t.Errorf("a pre-existing -wal was removed: %v", err)
	}
}

// TestReclaimSidecarsRefusesNonEmptyWAL covers the rule directly, without the
// timing of a real open: a WAL with frames in it is never deleted, whoever
// created it.
func TestReclaimSidecarsRefusesNonEmptyWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.sqlite")
	for _, f := range []struct {
		name string
		data []byte
	}{
		{path, []byte("db")},
		{path + "-wal", []byte("frames")},
		{path + "-shm", []byte("shm")},
	} {
		if err := os.WriteFile(f.name, f.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	reclaimSidecars(path)

	for _, suffix := range sidecarSuffixes {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Errorf("%s was removed despite a non-empty WAL: %v", suffix, err)
		}
	}
}

func TestReclaimSidecarsRemovesEmptyPair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.sqlite")
	if err := os.WriteFile(path, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range sidecarSuffixes {
		if err := os.WriteFile(path+suffix, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	reclaimSidecars(path)

	if after := dirEntries(t, dir); len(after) != 1 {
		t.Errorf("empty sidecars survived: %v", after)
	}
}

// An empty owned-path is the signal that there is nothing to reclaim — every
// non-read-only open. It must not touch the filesystem at all.
func TestReclaimSidecarsIgnoresEmptyPath(t *testing.T) {
	reclaimSidecars("")
}
