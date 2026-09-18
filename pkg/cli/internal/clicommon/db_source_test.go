package clicommon

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bug: a read command pointed at a path that does not exist opened it, which
// CREATED it, and then reported a successful empty result against the store it
// had just made. These assert the refusal and — just as important — that nothing
// appears on disk as a side effect of the check.

func TestCheckSourceExists_MissingIsRefusedAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "typo.sqlite")

	t.Cleanup(func() { RequireExistingSource = "" })
	RequireExistingSource = path

	err := checkSourceExists()
	if err == nil {
		t.Fatal("expected an error for a missing pinned source, got nil")
	}
	// Identity, not message text: this is what maps the failure to the
	// source_missing code and exit 1 in the CLI's classifier.
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error does not unwrap to fs.ErrNotExist: %v", err)
	}
	var missing *SourceMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *SourceMissingError, got %T", err)
	}
	if missing.Path != path {
		t.Errorf("Path = %q, want %q", missing.Path, path)
	}
	if entries, readErr := os.ReadDir(dir); readErr != nil {
		t.Fatal(readErr)
	} else if len(entries) != 0 {
		t.Errorf("the check created %d file(s) in the directory; it must create none", len(entries))
	}
}

func TestCheckSourceExists_ExistingPasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "real.sqlite")
	if err := os.WriteFile(path, []byte("not really sqlite, but it is there"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { RequireExistingSource = "" })
	RequireExistingSource = path

	// Present is all this check decides. Whether the file is a vigolium store is
	// a separate question with its own code (source_incompatible).
	if err := checkSourceExists(); err != nil {
		t.Errorf("expected nil for an existing file, got %v", err)
	}
}

func TestCheckSourceExists_DirectoryIsRefusedButNotAsMissing(t *testing.T) {
	dir := t.TempDir()

	t.Cleanup(func() { RequireExistingSource = "" })
	RequireExistingSource = dir

	err := checkSourceExists()
	if err == nil {
		t.Fatal("expected an error for a directory in place of a database file")
	}
	// A directory is present, so reporting it as missing would send the caller
	// looking for a path that is right there.
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a directory must not classify as source_missing: %v", err)
	}
}

func TestCheckSourceExists_UnarmedIsNoop(t *testing.T) {
	t.Cleanup(func() { RequireExistingSource = "" })
	RequireExistingSource = ""

	// The default database is still created on first use: a fresh install's first
	// `vigolium traffic` legitimately has nothing to read yet.
	if err := checkSourceExists(); err != nil {
		t.Errorf("expected nil when no source is pinned, got %v", err)
	}
}

// TestSourceIncompatibleErrorNamesThePath covers the other half of the pinned-
// source refusal: a file that opens as SQLite but is not a vigolium store.
//
// Before it, reading one CREATED vigolium's ~17 tables inside another tool's
// database and reported total: 0, exit 0 — a wrong path that both looked like an
// unscanned target and silently modified someone else's file.
func TestSourceIncompatibleErrorNamesThePath(t *testing.T) {
	err := error(&SourceIncompatibleError{Path: "/tmp/notes.sqlite"})

	if !strings.Contains(err.Error(), "/tmp/notes.sqlite") {
		t.Errorf("message does not name the file: %q", err)
	}
	// Must NOT read as missing: the file is right there, and sending the caller
	// to look for a path that exists is the wrong next move.
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("an incompatible store must not classify as source_missing")
	}
	var typed *SourceIncompatibleError
	if !errors.As(err, &typed) || typed.Path != "/tmp/notes.sqlite" {
		t.Errorf("errors.As did not recover the path: %+v", typed)
	}
}
