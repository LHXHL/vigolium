package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// TestResolveRecordUUID covers expanding a UUID prefix to the one record it
// names. Agents re-type these out of a JSON tool result, and 36 hex
// characters is more than they reliably copy - an observed run produced one
// UUID with an invented head and another that spliced two records together.
func TestResolveRecordUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saved := []*HTTPRecord{
		{UUID: "6d2f1ba9-d6f6-4d65-89ab-e118785919f3", URL: "https://example.test/a", Method: "GET"},
		{UUID: "6d2f0000-1111-2222-3333-444444444444", URL: "https://example.test/b", Method: "GET"},
		{UUID: "abcd1234-5555-6666-7777-888888888888", URL: "https://example.test/c", Method: "GET"},
	}
	if _, err := repo.SaveRecordsBatch(ctx, saved); err != nil {
		t.Fatalf("SaveRecordsBatch: %v", err)
	}

	t.Run("unique prefix expands", func(t *testing.T) {
		got, err := repo.ResolveRecordUUID(ctx, "abcd1234")
		if err != nil {
			t.Fatalf("ResolveRecordUUID: %v", err)
		}
		if got != saved[2].UUID {
			t.Errorf("got %q, want %q", got, saved[2].UUID)
		}
	})

	t.Run("full uuid still works", func(t *testing.T) {
		got, err := repo.ResolveRecordUUID(ctx, saved[0].UUID)
		if err != nil || got != saved[0].UUID {
			t.Errorf("got %q, %v; want the same uuid back", got, err)
		}
	})

	t.Run("ambiguous prefix names the candidates", func(t *testing.T) {
		_, err := repo.ResolveRecordUUID(ctx, "6d2f")
		if err == nil {
			t.Fatal("an ambiguous prefix must error rather than pick one")
		}
		if !strings.Contains(err.Error(), "matches 2 records") {
			t.Errorf("error should say how many matched: %v", err)
		}
		if !strings.Contains(err.Error(), saved[0].UUID) {
			t.Errorf("error should list the candidates: %v", err)
		}
	})

	t.Run("no match reports ErrNoRows", func(t *testing.T) {
		if _, err := repo.ResolveRecordUUID(ctx, "ffffffff"); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("got %v, want sql.ErrNoRows", err)
		}
	})

	// LIKE metacharacters are just characters in a range scan. The input is
	// a string a model may have mangled, so "%" must not match everything.
	t.Run("wildcards are literal", func(t *testing.T) {
		if _, err := repo.ResolveRecordUUID(ctx, "%"); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("a %% prefix matched something: %v", err)
		}
		if _, err := repo.ResolveRecordUUID(ctx, "abcd____"); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("an underscore prefix matched something: %v", err)
		}
	})
}

// TestGetRecordByUUIDOrPrefix covers the lookup both tools use: a full UUID
// costs one primary-key hit, a prefix falls back to the range scan, and an
// ambiguous prefix errors rather than picking one.
func TestGetRecordByUUIDOrPrefix(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	full := "6d2f1ba9-d6f6-4d65-89ab-e118785919f3"
	if _, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{
		{UUID: full, URL: "https://example.test/a", Method: "GET"},
		{UUID: "6d2f0000-1111-2222-3333-444444444444", URL: "https://example.test/b", Method: "GET"},
	}); err != nil {
		t.Fatalf("SaveRecordsBatch: %v", err)
	}

	got, err := repo.GetRecordByUUIDOrPrefix(ctx, full)
	if err != nil || got == nil || got.UUID != full {
		t.Fatalf("full uuid: got %v, %v", got, err)
	}
	got, err = repo.GetRecordByUUIDOrPrefix(ctx, "6d2f1ba9")
	if err != nil || got == nil || got.UUID != full {
		t.Fatalf("prefix: got %v, %v", got, err)
	}
	if _, err := repo.GetRecordByUUIDOrPrefix(ctx, "6d2f"); err == nil {
		t.Error("an ambiguous prefix must error")
	}
	if _, err := repo.GetRecordByUUIDOrPrefix(ctx, "ffffffff"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("unknown prefix: got %v, want sql.ErrNoRows", err)
	}
	// Too short to be a prefix: stays a plain miss, no scan.
	if _, err := repo.GetRecordByUUIDOrPrefix(ctx, "6d2f"[:3]); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("short input: got %v, want sql.ErrNoRows", err)
	}
}
