package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func redirectRR(t *testing.T, status int, location string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := "HTTP/1.1 " + map[int]string{301: "301 Moved Permanently", 302: "302 Found", 200: "200 OK", 304: "304 Not Modified"}[status] + "\r\n"
	if location != "" {
		raw += "Location: " + location + "\r\n"
	}
	raw += "Content-Length: 0\r\n\r\n"

	req := httpmsg.NewHttpRequest([]byte("GET /go HTTP/1.1\r\nHost: example.com\r\n\r\n")).
		WithService(httpmsg.NewServiceSecure("example.com", 443, true))
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(raw)))
}

// A redirect's destination is parsed once at ingestion, so the tree never has to
// read raw_response back to find it.
func TestConversionStoresRedirectLocation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		location string
		want     string
	}{
		{"absolute", 302, "https://example.com/after", "https://example.com/after"},
		{"relative stays relative", 301, "/after", "/after"},
		{"whitespace trimmed", 302, "  /after  ", "/after"},
		{"redirect without a location", 302, "", ""},
		{"not a redirect", 200, "/after", ""},
		{"304 is not a redirect", 304, "/after", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &HTTPRecord{}
			if err := rec.FromHttpRequestResponse(redirectRR(t, tc.status, tc.location)); err != nil {
				t.Fatalf("convert: %v", err)
			}
			if rec.ResponseLocation != tc.want {
				t.Fatalf("ResponseLocation = %q, want %q", rec.ResponseLocation, tc.want)
			}
		})
	}
}

// A record's stored destination must describe the response it currently holds.
// Replacing the response without updating the column left the old destination
// rendering against the new response.
func TestUpdateRecordResponseKeepsLocationConsistent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	const project = DefaultProjectUUID

	uuid, err := repo.SaveRecord(ctx, redirectRR(t, 302, "https://example.com/first"), "scanner", project)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, uuid); got != "https://example.com/first" {
		t.Fatalf("stored location = %q", got)
	}

	// Replay to a different destination.
	moved := []byte("HTTP/1.1 302 Found\r\nLocation: https://example.com/second\r\nContent-Length: 0\r\n\r\n")
	if err := repo.UpdateRecordResponse(ctx, uuid, &RecordResponseUpdate{
		StatusCode: 302, RawResponse: moved,
	}); err != nil {
		t.Fatalf("UpdateRecordResponse: %v", err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, uuid); got != "https://example.com/second" {
		t.Fatalf("after replay, stored location = %q, want the new destination", got)
	}

	// Replay to a non-redirect: the destination must be cleared, not kept.
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	if err := repo.UpdateRecordResponse(ctx, uuid, &RecordResponseUpdate{
		StatusCode: 200, RawResponse: ok,
	}); err != nil {
		t.Fatalf("UpdateRecordResponse: %v", err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, uuid); got != "" {
		t.Fatalf("a record that is no longer a redirect kept location %q", got)
	}
}

// A stub filled in by the backfill path must end up with the same derived data a
// normally-saved record has, the destination included.
func TestBackfillRecordResponseStoresLocation(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	insertHTTPRecord(t, db, "stub", DefaultProjectUUID)
	if err := repo.BackfillRecordResponse(ctx, "stub", redirectRR(t, 301, "/elsewhere")); err != nil {
		t.Fatalf("BackfillRecordResponse: %v", err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = 'stub'`); got != "/elsewhere" {
		t.Fatalf("backfilled location = %q, want /elsewhere", got)
	}
}

func scalarStr(t *testing.T, db *DB, q string, args ...any) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return s
}
