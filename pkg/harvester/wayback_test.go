package harvester

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaybackClient_Fetch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "url=*.example.com/*") {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}

		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "http://sub.example.com/api/v1")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	expected := []string{
		"http://example.com/page1",
		"http://example.com/page2",
		"http://sub.example.com/api/v1",
	}

	if len(got) != len(expected) {
		t.Errorf("got %d URLs, want %d", len(got), len(expected))
	}

	for i, want := range expected {
		if i >= len(got) {
			break
		}
		if got[i] != want {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestWaybackClient_Fetch_StreamsLineByLine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 1000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 1100)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lineCount := 0
	for range results {
		lineCount++
	}

	if lineCount != 1000 {
		t.Errorf("got %d lines, want 1000", lineCount)
	}
}

func TestWaybackClient_Fetch_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())

	results := make(chan Result, 200)
	go func() {
		count := 0
		for range results {
			count++
			if count >= 100 {
				cancel()
				return
			}
		}
	}()

	err := client.fetch(ctx, "example.com", results, "wayback")
	close(results)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestWaybackClient_Fetch_RateLimit_Retry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 1 || got[0] != "http://example.com/success" {
		t.Errorf("unexpected result: %v", got)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWaybackClient_Fetch_MaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 2,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_Fetch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *waybackAPIError
	if !errors.As(err, &apiErr) {
		t.Errorf("expected waybackAPIError, got: %T", err)
	}

	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestWaybackClient_Fetch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range results {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 URLs, got %d", count)
	}
}

func TestWaybackClient_Fetch_EmptyLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 2 {
		t.Errorf("expected 2 URLs, got %d: %v", len(got), got)
	}
}

func TestWaybackClient_Fetch_EmptyDomain(t *testing.T) {
	client := newWaybackClient()

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error for empty domain")
	}

	if !strings.Contains(err.Error(), "domain cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_BackoffCapped(t *testing.T) {
	var attempts int32
	var timestamps []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamps = append(timestamps, time.Now())
		count := atomic.AddInt32(&attempts, 1)
		if count < 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 5,
		retryDelay: 50 * time.Millisecond,
		maxBackoff: 100 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(timestamps) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", len(timestamps))
	}

	delay2 := timestamps[2].Sub(timestamps[1])
	delay3 := timestamps[3].Sub(timestamps[2])

	if delay3 > delay2*2 {
		t.Errorf("backoff should be capped: delay2=%v, delay3=%v", delay2, delay3)
	}
}

func TestWaybackSource_Run(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
	}))
	defer server.Close()

	src := &WaybackSource{
		client: &waybackClient{
			httpClient: server.Client(),
			baseURL:    server.URL,
			userAgent:  "test-agent",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			maxBackoff: 50 * time.Millisecond,
		},
	}

	results := src.Run(context.Background(), "example.com")

	var urls []string
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		urls = append(urls, r.URL)
	}

	if len(urls) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(urls))
	}
}

func TestNewWaybackClient_Defaults(t *testing.T) {
	client := newWaybackClient()

	if client.maxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", client.maxRetries)
	}

	if client.maxBackoff != 4*time.Second {
		t.Errorf("expected max backoff 4s, got %v", client.maxBackoff)
	}

	if client.retryDelay != 1*time.Second {
		t.Errorf("expected retry delay 1s, got %v", client.retryDelay)
	}
}

// --- mining ---------------------------------------------------------------

// waybackMineServer stands in for the archive: a CDX endpoint that answers both
// the domain query and the per-host robots.txt history, plus an `id_` replay
// endpoint serving raw captured bodies.
func waybackMineServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/cdx/search/cdx"):
			if strings.Contains(r.URL.RawQuery, "robots.txt") {
				// Two distinct versions, which is what collapse=digest buys.
				_, _ = fmt.Fprintln(w, "https://example.com/robots.txt 20150101000000")
				_, _ = fmt.Fprintln(w, "https://example.com/robots.txt 20230101000000")
				return
			}
			_, _ = fmt.Fprintln(w, "https://example.com/app.js 20200101000000 application/javascript 200")
			_, _ = fmt.Fprintln(w, "https://example.com/ 20200102000000 text/html 200")
			_, _ = fmt.Fprintln(w, "https://example.com/logo.png 20200103000000 image/png 200")

		case strings.Contains(r.URL.Path, "id_/"):
			switch {
			case strings.HasSuffix(r.URL.Path, "robots.txt"):
				_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /legacy-admin/\nSitemap: https://example.com/sitemap.xml\n")
			case strings.HasSuffix(r.URL.Path, "sitemap.xml"):
				_, _ = fmt.Fprint(w, `<urlset><url><loc>https://example.com/from-sitemap</loc></url></urlset>`)
			case strings.HasSuffix(r.URL.Path, "app.js"):
				_, _ = fmt.Fprint(w, `var api = "/api/v3/internal"; fetch("/api/v3/internal");`)
			default:
				_, _ = fmt.Fprint(w, `<a href="/linked-from-html">x</a>`)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestWaybackClient_MinesArchivedBodies(t *testing.T) {
	server := waybackMineServer(t)
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 1,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 20 * time.Millisecond,
	}

	results := make(chan Result, 500)
	if err := client.fetch(context.Background(), "example.com", results, "wayback"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(results)

	got := make(map[string]Result)
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected result error: %v", r.Error)
		}
		got[r.URL] = r
	}

	// The index rows are still emitted exactly as before.
	for _, want := range []string{
		"https://example.com/app.js",
		"https://example.com/",
		"https://example.com/logo.png",
	} {
		if r, ok := got[want]; !ok {
			t.Errorf("index URL %q missing", want)
		} else if r.Source != "wayback" || r.Mined {
			t.Errorf("index URL %q = %+v, want source \"wayback\" and Mined false", want, r)
		}
	}

	// Everything below exists in no CDX index: a path only robots.txt ever
	// named, a sitemap entry, and an endpoint written inside a script.
	for _, want := range []string{
		"https://example.com/legacy-admin/",
		"https://example.com/from-sitemap",
		"https://example.com/api/v3/internal",
		"https://example.com/linked-from-html",
	} {
		r, ok := got[want]
		if !ok {
			t.Errorf("mined URL %q missing", want)
			continue
		}
		// Provenance is a field, not a synthetic source name: every
		// Result.Source stays equal to some Source.Name().
		if r.Source != "wayback" || !r.Mined {
			t.Errorf("mined URL %q = %+v, want source \"wayback\" and Mined true", want, r)
		}
	}
}

// TestWaybackClient_SkipsMiningWithoutTimestamps locks in the gate that keeps a
// mining pass from firing against an index response that carries no timestamps.
// A replay is addressed by timestamp, so without one there is nothing to fetch —
// and firing anyway would spend a request per host to learn that.
func TestWaybackClient_SkipsMiningWithoutTimestamps(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = fmt.Fprintln(w, "https://example.com/page1")
		_, _ = fmt.Fprintln(w, "https://example.com/page2")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 1,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 20 * time.Millisecond,
	}

	results := make(chan Result, 50)
	if err := client.fetch(context.Background(), "example.com", results, "wayback"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(results)

	var count int
	for range results {
		count++
	}

	if count != 2 {
		t.Errorf("got %d URLs, want 2", count)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("made %d requests, want 1 (mining should not have run)", got)
	}
}

func TestParseCDXLine(t *testing.T) {
	tests := []struct {
		line string
		want cdxRow
	}{
		{
			line: "https://example.com/a 20200101000000 text/html 200",
			want: cdxRow{URL: "https://example.com/a", Timestamp: "20200101000000", MIME: "text/html", Status: "200"},
		},
		// A field list is a request, not a guarantee: a URL-only row still parses.
		{
			line: "https://example.com/a",
			want: cdxRow{URL: "https://example.com/a"},
		},
		{
			line: "https://example.com/a 20200101000000",
			want: cdxRow{URL: "https://example.com/a", Timestamp: "20200101000000"},
		},
		{line: "", want: cdxRow{}},
		{line: "   ", want: cdxRow{}},
	}

	for _, tt := range tests {
		if got := parseCDXLine(tt.line); got != tt.want {
			t.Errorf("parseCDXLine(%q) = %+v, want %+v", tt.line, got, tt.want)
		}
	}
}

func TestSelectRobotsHosts(t *testing.T) {
	rows := []cdxRow{
		{URL: "https://api.example.com/a"},
		{URL: "https://www.example.com/b"},
		{URL: "https://cdn.example.com/c"},
		{URL: "https://elsewhere.net/d"},
	}

	got := selectRobotsHosts(rows, "example.com")

	if len(got) != mineMaxRobotsHosts {
		t.Fatalf("got %d hosts, want %d: %v", len(got), mineMaxRobotsHosts, got)
	}
	// The apex leads: it is the host most likely to have been archived longest.
	if got[0] != "example.com" {
		t.Errorf("expected the apex first, got %v", got)
	}
	for _, host := range got {
		if host == "elsewhere.net" {
			t.Errorf("out-of-scope host selected: %v", got)
		}
	}
}

// --- paging, filters and the row cap ----------------------------------------

// cdxPagingServer fakes the CDX resumption protocol: rows are served
// limit-at-a-time, and a page with more behind it ends with a blank line and
// the (already URL-encoded) key of the next page. It records every index
// query it answers.
type cdxPagingServer struct {
	t       *testing.T
	rows    []string
	queries []url.Values
	raw     []string
	noKeys  bool // behave like a server that ignores showResumeKey
}

func (s *cdxPagingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.URL.Path, "/cdx/search/cdx") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if strings.Contains(q.Get("url"), "robots.txt") {
		return // no robots history
	}
	s.queries = append(s.queries, q)
	s.raw = append(s.raw, r.URL.RawQuery)

	start := 0
	if k := q.Get("resumeKey"); k != "" {
		// The key decodes to "key row-<n>"; anything else is a protocol error.
		n, err := strconv.Atoi(strings.TrimPrefix(k, "key row-"))
		if err != nil {
			s.t.Errorf("unexpected resumeKey %q", k)
			return
		}
		start = n
	}
	limit := len(s.rows)
	if l := q.Get("limit"); l != "" && !s.noKeys {
		limit, _ = strconv.Atoi(l)
	}
	if s.noKeys && q.Get("limit") != "" {
		// Ignores showResumeKey but honours limit: a full page, no key.
		limit, _ = strconv.Atoi(q.Get("limit"))
	}
	end := min(start+limit, len(s.rows))
	for _, row := range s.rows[start:end] {
		_, _ = fmt.Fprintln(w, row)
	}
	if end < len(s.rows) && q.Get("showResumeKey") == "true" && !s.noKeys {
		// Printed encoded, exactly like the archive does.
		_, _ = fmt.Fprintf(w, "\nkey+row-%d\n", end)
	}
}

func cdxRows(n int) []string {
	rows := make([]string, n)
	for i := range rows {
		rows[i] = fmt.Sprintf("https://example.com/p%d 2020010100000%d text/html 200", i, i%10)
	}
	return rows
}

func pagingClient(srvURL string, c *http.Client, pageSize, maxRows int) *waybackClient {
	return &waybackClient{
		httpClient: c,
		baseURL:    srvURL,
		userAgent:  "test-agent",
		maxRetries: 0,
		retryDelay: time.Millisecond,
		maxBackoff: time.Millisecond,
		pageSize:   pageSize,
		maxRows:    maxRows,
	}
}

func collect(t *testing.T, client *waybackClient) (urls, limits []string, err error) {
	t.Helper()
	results := make(chan Result, 10000)
	_, err = client.fetchIndex(context.Background(), "example.com", results, "wayback")
	close(results)
	for r := range results {
		switch {
		case r.Limit != "":
			limits = append(limits, r.Limit)
		case r.URL != "":
			urls = append(urls, r.URL)
		}
	}
	return urls, limits, err
}

func TestWaybackClient_FetchIndex_FiltersAndCollapse(t *testing.T) {
	fake := &cdxPagingServer{t: t, rows: cdxRows(3)}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	if _, _, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 0)); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 1 {
		t.Fatalf("queries = %d, want 1", len(fake.queries))
	}
	q := fake.queries[0]
	if q.Get("collapse") != "urlkey" {
		t.Errorf("collapse = %q, want urlkey", q.Get("collapse"))
	}
	filters := q["filter"]
	for _, want := range []string{"!statuscode:404", "!mimetype:(image|font|video|audio)/.*"} {
		if !slices.Contains(filters, want) {
			t.Errorf("filter %q missing from %v", want, filters)
		}
	}
	// Redirects and auth walls are real endpoints: never restrict to 200.
	if slices.Contains(filters, "statuscode:200") {
		t.Errorf("index must not be restricted to statuscode:200: %v", filters)
	}
	if q.Get("showResumeKey") != "true" || q.Get("limit") != "10" {
		t.Errorf("paging params = showResumeKey:%q limit:%q", q.Get("showResumeKey"), q.Get("limit"))
	}
	if !strings.Contains(fake.raw[0], "url=*.example.com/*") {
		t.Errorf("domain pattern changed: %s", fake.raw[0])
	}
}

func TestWaybackClient_FetchIndex_ResumeKeyPaging(t *testing.T) {
	fake := &cdxPagingServer{t: t, rows: cdxRows(25)}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	urls, limits, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 25 {
		t.Fatalf("got %d URLs, want 25 (the resume key must not be emitted as a URL)", len(urls))
	}
	for i, u := range urls {
		if want := fmt.Sprintf("https://example.com/p%d", i); u != want {
			t.Fatalf("url[%d] = %q, want %q", i, u, want)
		}
	}
	if len(limits) != 0 {
		t.Errorf("unexpected limits %v", limits)
	}
	if len(fake.queries) != 3 {
		t.Fatalf("pages fetched = %d, want 3", len(fake.queries))
	}
	if fake.queries[0].Get("resumeKey") != "" {
		t.Error("first page must not carry a resumeKey")
	}
	// The key goes back verbatim: "+" is the archive's own encoding of a space.
	if !strings.Contains(fake.raw[1], "resumeKey=key+row-10") || !strings.Contains(fake.raw[2], "resumeKey=key+row-20") {
		t.Errorf("resume keys not passed back verbatim: %q / %q", fake.raw[1], fake.raw[2])
	}
}

func TestWaybackClient_FetchIndex_MaxRowsCap(t *testing.T) {
	fake := &cdxPagingServer{t: t, rows: cdxRows(50)}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	urls, limits, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 25))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 25 {
		t.Errorf("got %d URLs, want the 25-row cap", len(urls))
	}
	if !slices.Equal(limits, []string{LimitCDXMaxRows}) {
		t.Errorf("limits = %v, want [%s]", limits, LimitCDXMaxRows)
	}
	if len(fake.queries) != 3 {
		t.Errorf("pages fetched = %d, want 3 (no page past the cap)", len(fake.queries))
	}
}

func TestWaybackClient_FetchIndex_CapOnPageBoundary(t *testing.T) {
	// Exactly max_rows rows exist: reaching the cap with nothing behind it is
	// not a limit.
	fake := &cdxPagingServer{t: t, rows: cdxRows(20)}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	urls, limits, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 20))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 20 || len(limits) != 0 {
		t.Errorf("urls=%d limits=%v, want 20 and none", len(urls), limits)
	}

	// One more row than the cap: now it is.
	fake.rows = cdxRows(21)
	fake.queries, fake.raw = nil, nil
	urls, limits, err = collect(t, pagingClient(srv.URL, srv.Client(), 10, 20))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 20 || !slices.Equal(limits, []string{LimitCDXMaxRows}) {
		t.Errorf("urls=%d limits=%v, want 20 and [%s]", len(urls), limits, LimitCDXMaxRows)
	}
}

func TestWaybackClient_FetchIndex_NoResumeKeyFallback(t *testing.T) {
	// A server that ignores showResumeKey hands back a full first page and no
	// key; the client re-reads once unpaged and skips what it already emitted.
	fake := &cdxPagingServer{t: t, rows: cdxRows(25), noKeys: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	urls, limits, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 25 {
		t.Fatalf("got %d URLs, want 25", len(urls))
	}
	seen := map[string]bool{}
	for _, u := range urls {
		if seen[u] {
			t.Errorf("duplicate %q emitted by the fallback", u)
		}
		seen[u] = true
	}
	if len(limits) != 0 {
		t.Errorf("unexpected limits %v", limits)
	}
	if len(fake.queries) != 2 || fake.queries[1].Get("limit") != "" || fake.queries[1].Get("showResumeKey") != "" {
		t.Errorf("want one paged query then one unpaged one, got %v", fake.queries)
	}
	// The unpaged retry keeps the server-side filters.
	if fake.queries[1].Get("collapse") != "urlkey" || len(fake.queries[1]["filter"]) != 2 {
		t.Errorf("fallback query lost collapse/filters: %v", fake.queries[1])
	}
}

func TestWaybackClient_FetchIndex_ShortPageNoKeyIsDone(t *testing.T) {
	fake := &cdxPagingServer{t: t, rows: cdxRows(4), noKeys: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	urls, _, err := collect(t, pagingClient(srv.URL, srv.Client(), 10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 4 || len(fake.queries) != 1 {
		t.Errorf("urls=%d queries=%d, want 4 and 1", len(urls), len(fake.queries))
	}
}

func TestWaybackClient_FetchIndex_RepeatedKeyStops(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = fmt.Fprintln(w, "https://example.com/a 20200101000000 text/html 200")
		_, _ = fmt.Fprint(w, "\nstuck-key\n")
	}))
	defer srv.Close()

	if _, _, err := collect(t, pagingClient(srv.URL, srv.Client(), 1, 0)); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("calls = %d, want 2 (stop once the key repeats)", n)
	}
}

func TestReadIndexPage_BlankLineThenURLIsARow(t *testing.T) {
	// A blank line followed by more rows is not a resume-key trailer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "https://example.com/a\n\nhttps://example.com/b\n\nopaque-key\n\n")
	}))
	defer srv.Close()

	c := pagingClient(srv.URL, srv.Client(), 10, 0)
	var got []string
	key, n, err := c.readIndexPage(context.Background(), srv.URL+"/cdx/search/cdx", func(row cdxRow) (bool, error) {
		got = append(got, row.URL)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if key != "opaque-key" || n != 2 || !slices.Equal(got, []string{"https://example.com/a", "https://example.com/b"}) {
		t.Errorf("key=%q n=%d rows=%v", key, n, got)
	}
}

func TestWaybackSource_SetCDXBounds(t *testing.T) {
	s := NewWaybackSource()
	s.setCDXBounds(500, 0) // harvester's resolved "unbounded"
	if page, max := s.client.cdxBounds(); page != 500 || max != 0 {
		t.Errorf("bounds = %d/%d, want 500/0 (unbounded)", page, max)
	}
	s.setCDXBounds(500, 42)
	if _, max := s.client.cdxBounds(); max != 42 {
		t.Errorf("max = %d, want 42", max)
	}
}
