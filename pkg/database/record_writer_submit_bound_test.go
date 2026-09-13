package database

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// makeSizedPair builds a request/response pair with a body of roughly bodyLen
// bytes and a unique path, so records neither dedup onto each other nor collide.
func makeSizedPair(t testing.TB, i, bodyLen int) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := fmt.Sprintf("GET /bound/%d HTTP/1.1\r\nHost: bound.example.com\r\n\r\n", i)
	req, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest(%d): %v", i, err)
	}
	req = req.WithService(httpmsg.NewServiceSecure("bound.example.com", 443, true))
	body := strings.Repeat("x", bodyLen)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
	return req.WithResponse(httpmsg.NewHttpResponse([]byte(resp)))
}

// TestSaveRecordBatchSplitsSubmissionsKeepsAlignment is the guard on chunking:
// a bulk submission is now admitted in slices, and every returned UUID must
// still line up with its input index across those slice boundaries.
func TestSaveRecordBatchSplitsSubmissionsKeepsAlignment(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	// Force many slices for a modest input.
	w := NewRecordWriter(repo, RecordWriterConfig{MaxSubmitRecords: 7})
	defer w.Close()

	const n = 50
	records := make([]*httpmsg.HttpRequestResponse, n)
	for i := range records {
		records[i] = makeSizedPair(t, i, 64)
	}

	uuids, err := w.SaveRecordBatch(context.Background(), records, "bound-test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecordBatch: %v", err)
	}
	if len(uuids) != n {
		t.Fatalf("got %d uuids, want %d", len(uuids), n)
	}

	seen := make(map[string]bool, n)
	for i, u := range uuids {
		if u == "" {
			t.Fatalf("uuids[%d] is empty", i)
		}
		if seen[u] {
			t.Fatalf("uuids[%d] = %q is a duplicate; slices lost alignment", i, u)
		}
		seen[u] = true

		// The stored row at this UUID must be the record submitted at this index.
		rec, err := repo.GetRecordByUUID(context.Background(), u)
		if err != nil {
			t.Fatalf("GetRecordByUUID(%q) for index %d: %v", u, i, err)
		}
		wantPath := fmt.Sprintf("/bound/%d", i)
		if rec.Path != wantPath {
			t.Errorf("uuids[%d] points at %q, want %q — positional alignment broke across a slice boundary",
				i, rec.Path, wantPath)
		}
	}
}

// TestSubmitSliceEndBounds checks the slicing arithmetic directly, including the
// oversized-record case that must never produce an empty slice.
func TestSubmitSliceEndBounds(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	t.Run("bounded by record count", func(t *testing.T) {
		w := NewRecordWriter(repo, RecordWriterConfig{MaxSubmitRecords: 4})
		defer w.Close()
		records := make([]*httpmsg.HttpRequestResponse, 10)
		for i := range records {
			records[i] = makeSizedPair(t, i, 16)
		}
		if got := w.submitSliceEnd(records, 0); got != 4 {
			t.Errorf("submitSliceEnd = %d, want 4", got)
		}
		if got := w.submitSliceEnd(records, 8); got != 10 {
			t.Errorf("submitSliceEnd near the end = %d, want 10", got)
		}
	})

	t.Run("bounded by bytes", func(t *testing.T) {
		records := make([]*httpmsg.HttpRequestResponse, 10)
		for i := range records {
			records[i] = makeSizedPair(t, i, 1000)
		}
		// Room for about two records per slice.
		w := NewRecordWriter(repo, RecordWriterConfig{
			MaxSubmitRecords: 1000,
			MaxSubmitBytes:   2 * recordWireSize(records[0]),
		})
		defer w.Close()

		got := w.submitSliceEnd(records, 0)
		if got != 2 {
			t.Errorf("submitSliceEnd = %d, want 2 (byte bound)", got)
		}
	})

	t.Run("a single oversized record still advances", func(t *testing.T) {
		w := NewRecordWriter(repo, RecordWriterConfig{
			MaxSubmitRecords: 1000,
			MaxSubmitBytes:   1, // smaller than any real record
		})
		defer w.Close()
		records := []*httpmsg.HttpRequestResponse{
			makeSizedPair(t, 0, 4096),
			makeSizedPair(t, 1, 4096),
		}
		if got := w.submitSliceEnd(records, 0); got != 1 {
			t.Fatalf("submitSliceEnd = %d, want 1 — an oversized record must be submitted alone, never skipped", got)
		}
	})
}

// TestSaveRecordBatchBoundedSubmissionStillDedups confirms slicing did not
// disturb dedup: the same record repeated across slice boundaries resolves to
// one row.
func TestSaveRecordBatchBoundedSubmissionStillDedups(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewRecordWriter(repo, RecordWriterConfig{MaxSubmitRecords: 3})
	defer w.Close()

	dup := makeSizedPair(t, 99, 32)
	records := make([]*httpmsg.HttpRequestResponse, 12)
	for i := range records {
		records[i] = dup
	}

	uuids, err := w.SaveRecordBatch(context.Background(), records, "bound-test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecordBatch: %v", err)
	}
	for i, u := range uuids {
		if u != uuids[0] {
			t.Fatalf("uuids[%d] = %q, want every duplicate to resolve to %q", i, u, uuids[0])
		}
	}
}
