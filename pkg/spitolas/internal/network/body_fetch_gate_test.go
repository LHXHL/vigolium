package network

import (
	"os"
	"strings"
	"testing"
)

// TestShouldFetchResponseBody locks in the body-fetch skip gate: HTML/JS/JSON/
// XML/API responses are always fetched (they drive discovery), while binary
// static assets are fetched only when retained and under the size cap. Skipping
// a discarded static body also skips that response's page enumeration + CDP
// body transfer — the dominant per-response cost.
func TestShouldFetchResponseBody(t *testing.T) {
	entry := func(ct, url string) *TrafficEntry {
		return &TrafficEntry{
			ContentType: ct,
			Request:     RequestData{URL: url},
			Response:    &ResponseData{Status: 200},
		}
	}

	cases := []struct {
		name        string
		entry       *TrafficEntry
		includeBody bool
		encodedLen  float64
		want        bool
	}{
		{"html always fetched", entry("text/html", "https://x/index"), false, 0, true},
		{"json always fetched", entry("application/json", "https://x/api/users"), false, 0, true},
		{"javascript always fetched", entry("application/javascript", "https://x/app.js"), false, 0, true},
		{"xml always fetched", entry("text/xml", "https://x/feed"), false, 0, true},
		{"image discarded → skip", entry("image/png", "https://x/logo.png"), false, 0, false},
		{"font discarded → skip", entry("font/woff2", "https://x/f.woff2"), false, 0, false},
		{"static by extension discarded → skip", entry("", "https://x/a.css"), false, 0, false},
		{"image retained + small → fetch", entry("image/png", "https://x/logo.png"), true, 1000, true},
		{"image retained + oversized → skip", entry("image/png", "https://x/huge.png"), true, maxStaticBodyFetchBytes + 1, false},
		{"nil response → skip", &TrafficEntry{Request: RequestData{URL: "https://x/y"}}, true, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFetchResponseBody(tc.entry, tc.includeBody, tc.encodedLen); got != tc.want {
				t.Errorf("shouldFetchResponseBody = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBodyGateSeesContentTypeFromHeaders covers the ordering the table above
// cannot: every case there hand-sets ContentType, which is precisely what hid
// the defect. On the real path ContentType is derived from the response headers,
// and it used to be derived only AFTER the gate had already run — so the gate
// saw "" on every response and could classify a static asset only by its URL
// suffix. An extensionless image was therefore treated as an API response:
// fetched over CDP regardless of size and retained in full, with the
// maxStaticBodyFetchBytes cap never consulted.
//
// The entries here are built the way onLoadingFinished builds them (headers
// populated, ContentType empty) so the assertion fails if the computeHeaderFields
// call is ever moved back below the gate.
func TestBodyGateSeesContentTypeFromHeaders(t *testing.T) {
	// headerEntry mirrors onResponseReceived: headers are known, ContentType is not.
	headerEntry := func(ct, url string) *TrafficEntry {
		return &TrafficEntry{
			Request:  RequestData{URL: url},
			Response: &ResponseData{Status: 200, Headers: map[string]string{"Content-Type": ct}},
		}
	}

	cases := []struct {
		name        string
		ct          string
		url         string
		includeBody bool
		encodedLen  float64
		want        bool
	}{
		// The regression case: no suffix to fall back on, so the MIME type is the
		// only thing that can classify it. Oversized and retained → must be skipped.
		{"extensionless oversized image → skip", "image/png", "https://x/media/4821", true, 6 * 1024 * 1024, false},
		{"extensionless image discarded → skip", "image/png", "https://x/media/4821", false, 0, false},
		{"extensionless font discarded → skip", "font/woff2", "https://x/assets/f1", false, 0, false},
		{"extensionless video discarded → skip", "video/mp4", "https://x/stream/9", false, 0, false},
		// A charset parameter must not defeat the classification.
		{"image with charset param → skip", "image/svg+xml; charset=utf-8", "https://x/i/7", false, 0, false},
		// Text/API responses stay unconditionally fetched — they drive discovery.
		{"extensionless json → fetch", "application/json", "https://x/api/users/1", false, 0, true},
		{"extensionless html → fetch", "text/html; charset=utf-8", "https://x/dashboard", false, 0, true},
		// A retained, small static asset is still worth fetching.
		{"extensionless small image retained → fetch", "image/png", "https://x/media/4821", true, 2048, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := headerEntry(tc.ct, tc.url)
			if entry.ContentType != "" {
				t.Fatalf("fixture is wrong: ContentType must start empty, got %q", entry.ContentType)
			}

			// This is the production ordering under test.
			computeHeaderFields(entry)

			if entry.ContentType != tc.ct {
				t.Fatalf("computeHeaderFields did not resolve Content-Type: got %q, want %q",
					entry.ContentType, tc.ct)
			}
			if got := shouldFetchResponseBody(entry, tc.includeBody, tc.encodedLen); got != tc.want {
				t.Errorf("shouldFetchResponseBody = %v, want %v (content-type %q, url %q)",
					got, tc.want, tc.ct, tc.url)
			}
		})
	}
}

// TestHeaderFieldsResolvedBeforeBodyGate is the ordering guard the two tests
// above cannot express: they call computeHeaderFields themselves, so they prove
// the function works, not that onLoadingFinished calls it in time. The defect
// was purely one of ordering — both functions were correct in isolation — so the
// regression this must catch is a future edit moving the call back below the
// gate, where entry.ContentType is empty again and the MIME branch goes dead.
func TestHeaderFieldsResolvedBeforeBodyGate(t *testing.T) {
	src, err := os.ReadFile("capture.go")
	if err != nil {
		t.Fatalf("read capture.go: %v", err)
	}

	fn := string(src)
	start := strings.Index(fn, "func (c *Capture) onLoadingFinished(")
	if start == -1 {
		t.Fatal("onLoadingFinished not found; update this guard")
	}
	body := fn[start:]
	if end := strings.Index(body, "\nfunc "); end != -1 {
		body = body[:end]
	}

	resolve := strings.Index(body, "computeHeaderFields(pending.entry)")
	gate := strings.Index(body, "shouldFetchResponseBody(pending.entry")
	switch {
	case resolve == -1:
		t.Fatal("onLoadingFinished no longer resolves the header fields; " +
			"shouldFetchResponseBody would read an empty ContentType on every response")
	case gate == -1:
		t.Fatal("body-fetch gate not found in onLoadingFinished; update this guard")
	case resolve > gate:
		t.Error("computeHeaderFields must be called BEFORE shouldFetchResponseBody — " +
			"the gate reads entry.ContentType, so resolving it afterwards leaves the " +
			"isBinaryStaticContentType branch dead and lets extensionless media bypass " +
			"the maxStaticBodyFetchBytes cap")
	}
}

// TestComputeHTTPXFieldsStillResolvesHeaders guards the split: computeHeaderFields
// was extracted out of computeHTTPXFields, and callers that only reach the latter
// must keep getting both header fields.
func TestComputeHTTPXFieldsStillResolvesHeaders(t *testing.T) {
	entry := &TrafficEntry{
		Request: RequestData{URL: "https://x/page"},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"Content-Type": "text/html", "Server": "nginx/1.25"},
			Body:    []byte("hello world\nsecond line\n"),
		},
	}

	computeHTTPXFields(entry)

	if entry.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want text/html", entry.ContentType)
	}
	if entry.WebServer != "nginx/1.25" {
		t.Errorf("WebServer = %q, want nginx/1.25", entry.WebServer)
	}
	if entry.ContentLength != len(entry.Response.Body) {
		t.Errorf("ContentLength = %d, want %d", entry.ContentLength, len(entry.Response.Body))
	}
	if entry.Words != 4 {
		t.Errorf("Words = %d, want 4", entry.Words)
	}

	// Calling it twice must be idempotent — onLoadingFinished now resolves the
	// header fields before the gate and computeHTTPXFields resolves them again
	// after the body arrives.
	computeHTTPXFields(entry)
	if entry.ContentType != "text/html" || entry.WebServer != "nginx/1.25" {
		t.Error("header field resolution is not idempotent")
	}
}
