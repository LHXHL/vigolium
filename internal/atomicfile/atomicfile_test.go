package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBytesReplacesCleanlyAndIsReadable(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "body.json")

	if err := WriteBytes(dest, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("WriteBytes: %v", err)
	}
	if data, err := os.ReadFile(dest); err != nil {
		t.Fatal(err)
	} else if string(data) != `{"a":1}` {
		t.Errorf("contents = %q", data)
	}

	if err := WriteBytes(dest, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("second write: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("temporary files survived the rename: %v", names)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	// CreateTemp's 0600 would make every artifact the CLI writes owner-only,
	// which is not what a file the caller named should be.
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

// A failed write must leave any existing destination exactly as it was — the
// whole reason for temp-and-rename over a direct open.
func TestWriteBytesLeavesDestinationOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "evidence.bin")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := WriteBytes(dest, []byte("replacement")); err == nil {
		t.Fatal("expected a failure writing into a read-only directory")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("destination was damaged by a failed write: %q", data)
	}
}
