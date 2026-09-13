package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestSaveRecordBatchKeepsPositionalAlignment pins the contract discovery relies
// on: the returned UUID slice is index-aligned with the input, carrying "" for a
// record that failed conversion. Compacting the slice instead shifted every UUID
// after a failure onto the preceding request, so findings were linked to the
// wrong HTTP record.
func TestSaveRecordBatchKeepsPositionalAlignment(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Index 1 fails conversion (nil request); 0, 2 and 3 are valid.
	records := []*httpmsg.HttpRequestResponse{
		makeTestGet(t, "/first", ""),
		httpmsg.NewHttpRequestResponse(nil, nil),
		makeTestGet(t, "/third", ""),
		makeTestGet(t, "/fourth", ""),
	}

	uuids, err := repo.SaveRecordBatch(ctx, records, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecordBatch: %v", err)
	}

	if len(uuids) != len(records) {
		t.Fatalf("expected %d uuids (one per input), got %d", len(records), len(uuids))
	}
	if uuids[1] != "" {
		t.Errorf("index 1 failed conversion, want empty uuid, got %q", uuids[1])
	}
	for _, i := range []int{0, 2, 3} {
		if uuids[i] == "" {
			t.Errorf("index %d converted fine but got no uuid", i)
		}
	}

	// The decisive assertion: each returned UUID must resolve to the record that
	// sat at that exact input index, not the one before it.
	for _, tc := range []struct {
		idx  int
		path string
	}{{0, "/first"}, {2, "/third"}, {3, "/fourth"}} {
		rec, err := repo.GetRecordByUUID(ctx, uuids[tc.idx])
		if err != nil {
			t.Fatalf("index %d: lookup %s: %v", tc.idx, uuids[tc.idx], err)
		}
		if rec.Path != tc.path {
			t.Errorf("index %d: uuid points at path %q, want %q (alignment skew)", tc.idx, rec.Path, tc.path)
		}
	}
}
