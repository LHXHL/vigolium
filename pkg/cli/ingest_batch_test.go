package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetIngestBatchState(t *testing.T) {
	t.Helper()
	prevTyped, prevDir, prevGlob := ingestTypedInputs, ingestDir, ingestDirGlob
	ingestTypedInputs, ingestDir, ingestDirGlob = nil, "", "*"
	t.Cleanup(func() {
		ingestTypedInputs, ingestDir, ingestDirGlob = prevTyped, prevDir, prevGlob
	})
}

func TestIngestInputSourcesKeepsEveryTypedInput(t *testing.T) {
	// pflag stores only the LAST -i, so without the typed list the FIRST file is
	// silently dropped and the command reports success having ingested one of two.
	resetIngestBatchState(t)
	ingestTypedInputs = []string{"a.har", "b.har"}

	got, err := ingestInputSources("b.har") // what pflag left in the variable
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "a.har,b.har" {
		t.Errorf("sources = %v, want [a.har b.har] in typed order", got)
	}
}

func TestIngestInputSourcesDedups(t *testing.T) {
	resetIngestBatchState(t)
	ingestTypedInputs = []string{"a.har", "a.har"}
	got, err := ingestInputSources("a.har")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("sources = %v, want one entry", got)
	}
}

func TestIngestInputSourcesDropsStdinSentinel(t *testing.T) {
	// "-" means stdin, which is not a file to iterate over.
	resetIngestBatchState(t)
	got, err := ingestInputSources("-")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("sources = %v, want none", got)
	}
}

func TestExpandIngestDirSortsAndFilters(t *testing.T) {
	// Sorted so a re-run is reproducible: record ids are assigned in ingest order.
	resetIngestBatchState(t)
	dir := t.TempDir()
	for _, name := range []string{"b.har", "a.har", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := expandIngestDir(dir, "*.har")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || filepath.Base(got[0]) != "a.har" || filepath.Base(got[1]) != "b.har" {
		t.Errorf("expandIngestDir = %v, want [a.har b.har]", got)
	}
}

func TestExpandIngestDirIsNotRecursive(t *testing.T) {
	// Walking subdirectories would silently widen what the caller pointed at.
	resetIngestBatchState(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep.har"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "top.har"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := expandIngestDir(dir, "*.har")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0]) != "top.har" {
		t.Errorf("expandIngestDir = %v, want only the top-level file", got)
	}
}

func TestExpandIngestDirEmptyMatchIsAnError(t *testing.T) {
	// "ingested 0 records" for a typo'd path is indistinguishable from an empty
	// capture, so an empty expansion fails instead.
	resetIngestBatchState(t)
	if _, err := expandIngestDir(t.TempDir(), "*.har"); err == nil {
		t.Error("empty match accepted")
	}
}

func TestAccumulatingStringRecordsEverySet(t *testing.T) {
	resetIngestBatchState(t)
	var dest string
	var seen []string
	inner := &testStringValue{v: &dest}
	acc := &accumulatingString{inner: inner, seen: &seen}

	for _, v := range []string{"a", "b", "c"} {
		if err := acc.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(seen, ",") != "a,b,c" {
		t.Errorf("seen = %v, want all three in order", seen)
	}
	// The flag still reports the last value, which is what globalInput's existing
	// readers expect.
	if acc.String() != "c" {
		t.Errorf("String() = %q, want the last value", acc.String())
	}
}

type testStringValue struct{ v *string }

func (s *testStringValue) String() string     { return *s.v }
func (s *testStringValue) Type() string       { return "string" }
func (s *testStringValue) Set(v string) error { *s.v = v; return nil }
