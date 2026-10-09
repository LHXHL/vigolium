package database

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/vigolium/vigolium/pkg/work"
)

// drainCount reads src to EOF, completing every item, and returns how many it
// served.
func drainCount(t *testing.T, next func(context.Context) (*work.WorkItem, error)) int64 {
	t.Helper()
	var n int64
	for {
		item, err := next(context.Background())
		if errors.Is(err, io.EOF) {
			return n
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		n++
		item.Complete()
	}
}

// TestDBInputSourceCountMatchesIteration: the Count snapshot taken on the first
// fetch is over exactly the rows iteration walks (same cursor, host scope and
// project filters), and is 0 — "unknown" — before the first Next, so the
// executor's construction-time read of it is unchanged.
func TestDBInputSourceCountMatchesIteration(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	scanUUID := createTestScan(t, repo)

	const host = "count.example.com"
	insertTestRecordsWithHost(t, repo, host, 7)
	insertTestRecordsWithHost(t, repo, "other.example.com", 4) // out of scope

	src := NewOneShotDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}}).
		WithPageSize(3) // several pages, one count
	if got := src.Count(); got != 0 {
		t.Fatalf("Count before the first Next = %d, want 0", got)
	}
	served := drainCount(t, src.Next)
	if served != 7 {
		t.Fatalf("served %d records, want 7", served)
	}
	if got := src.Count(); got != served {
		t.Errorf("Count = %d, want %d (the records iteration served)", got, served)
	}
}

// TestRiskPrioritizedDBInputSourceCountMatchesIteration: the snapshot window's
// count equals what the round serves when coalescing is off.
func TestRiskPrioritizedDBInputSourceCountMatchesIteration(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	scanUUID := createTestScan(t, repo)

	const host = "risk-count.example.com"
	insertTestRecordsWithHost(t, repo, host, 5)
	insertTestRecordsWithHost(t, repo, "elsewhere.example.com", 3)

	src := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).
		WithHostScopes([]HostTarget{{Hostname: host}})
	if got := src.Count(); got != 0 {
		t.Fatalf("Count before the first Next = %d, want 0", got)
	}
	served := drainCount(t, src.Next)
	if served != 5 {
		t.Fatalf("served %d records, want 5", served)
	}
	if got := src.Count(); got != served {
		t.Errorf("Count = %d, want %d", got, served)
	}
}
