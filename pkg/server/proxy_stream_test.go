package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// TestCaptureBuffer verifies the bounded capture writer keeps only a prefix,
// reports truncation once the stream exceeds the limit, and never short-writes
// (so it can't throttle the io.Copy driving the forward).
func TestCaptureBuffer(t *testing.T) {
	c := &captureBuffer{limit: 4}

	n, err := c.Write([]byte("ab"))
	if err != nil || n != 2 {
		t.Fatalf("Write = (%d, %v), want (2, nil)", n, err)
	}
	if c.truncated() {
		t.Fatal("should not be truncated at 2/4 bytes")
	}

	// Writing 4 more takes total to 6 (> limit 4): reports full length, keeps 4.
	if n, _ := c.Write([]byte("cdef")); n != 4 {
		t.Fatalf("Write returned %d, want full 4 even past the limit", n)
	}
	if !c.truncated() {
		t.Fatal("should be truncated once total exceeds the limit")
	}
	if got := string(c.Bytes()); got != "abcd" {
		t.Fatalf("captured %q, want the 4-byte prefix %q", got, "abcd")
	}
	if c.total != 6 {
		t.Fatalf("total = %d, want 6", c.total)
	}
}

// plainProxyClient starts an ingest proxy (no MITM) in front of the given DB and
// returns an HTTP client routed through it.
func plainProxyClient(t *testing.T, db *database.DB, repo *database.Repository) *http.Client {
	t.Helper()
	proxySrv := newIngestProxy("127.0.0.1:0", db, repo, nil, nil,
		nil, nil, false, nil)
	proxyURL := startProxy(t, proxySrv)
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
}

// TestIngestProxy_ForwardsFullBodyOverCaptureLimit is the core regression guard
// for the capture-vs-forward invariant: a response larger than the recording cap
// must still reach the client byte-for-byte. Before the streaming fix the proxy
// read only a capped prefix and forwarded that truncated body.
func TestIngestProxy_ForwardsFullBodyOverCaptureLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a >10 MB body")
	}
	bodyLen := defaultMaxProxyBodySize + 1<<20 // 11 MB — past the recording cap
	payload := bytes.Repeat([]byte("A"), bodyLen)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	db, repo := newPinnedTestDB(t)
	client := plainProxyClient(t, db, repo)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read proxied body: %v", err)
	}
	if len(got) != bodyLen {
		t.Fatalf("client received %d bytes, want the full %d — the recording cap must never truncate forwarded traffic", len(got), bodyLen)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("forwarded body differs from upstream body")
	}
}

// TestIngestProxy_PlainHTTPRecordsNormalBody confirms the streaming path still
// records a normal (sub-cap) transaction faithfully.
func TestIngestProxy_PlainHTTPRecordsNormalBody(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up listeners")
	}
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	if err := repo.CreateProject(ctx, &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	const marker = "PLAIN-BODY-MARKER-42a1"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, marker)
	}))
	defer upstream.Close()

	client := plainProxyClient(t, db, repo)
	resp, err := client.Get(upstream.URL + "/plain")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != marker {
		t.Fatalf("client body = %q, want %q", body, marker)
	}

	rec := waitForHostRecord(t, ctx, repo, "127.0.0.1")
	if rec == nil {
		t.Fatal("proxy did not record the plain-HTTP transaction")
	}
	if !strings.Contains(string(rec.RawResponse), marker) {
		t.Errorf("recorded response missing body marker; got %q", rec.RawResponse)
	}
}
