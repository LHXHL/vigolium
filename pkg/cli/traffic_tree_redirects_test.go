package cli

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// TestRedirectLocationReadsResponseHeader covers the one thing the tree's
// redirect display rests on: that the Location is recoverable from the stored
// response bytes, whose first line is a status line rather than a request line.
func TestRedirectLocationReadsResponseHeader(t *testing.T) {
	rec := &database.HTTPRecord{
		StatusCode:  302,
		HasResponse: true,
		RawResponse: []byte("HTTP/1.1 302 Found\r\n" +
			"Server: nginx\r\n" +
			"Location: https://example.com/login?next=%2Fadmin\r\n" +
			"Content-Length: 0\r\n\r\n"),
	}
	if got := redirectLocation(rec); got != "https://example.com/login?next=%2Fadmin" {
		t.Fatalf("redirectLocation = %q", got)
	}
	if suffix := treeRecordSuffix(rec); !strings.Contains(suffix, "https://example.com/login?next=%2Fadmin") {
		t.Fatalf("tree suffix does not carry the destination: %q", suffix)
	}
}

// TestRedirectLocationSkipsNonRedirects guards the two ways this would render a
// destination that is not one: a 2xx that happens to carry Location (a 201's
// Location is the created resource, not a redirect), and a 304, which is a cache
// validator with nowhere to go.
func TestRedirectLocationSkipsNonRedirects(t *testing.T) {
	for _, status := range []int{200, 201, 304, 404} {
		rec := &database.HTTPRecord{
			StatusCode:  status,
			HasResponse: true,
			RawResponse: []byte("HTTP/1.1 200 OK\r\nLocation: /created/1\r\n\r\n"),
		}
		if got := redirectLocation(rec); got != "" {
			t.Fatalf("status %d: redirectLocation = %q, want empty", status, got)
		}
	}
}

// TestRedirectLocationWithoutRawResponse pins the degraded case: when the list
// query projected the bodies away and hydration could not reach the record, the
// line renders without a destination rather than failing.
func TestRedirectLocationWithoutRawResponse(t *testing.T) {
	rec := &database.HTTPRecord{StatusCode: 302, HasResponse: true}
	if got := redirectLocation(rec); got != "" {
		t.Fatalf("redirectLocation = %q, want empty", got)
	}
	if suffix := treeRecordSuffix(rec); !strings.Contains(suffix, "302") {
		t.Fatalf("tree suffix lost the status: %q", suffix)
	}
}
