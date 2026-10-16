package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeBridge is a loopback httptest server standing in for the extension's
// listener. handler receives the decoded request body and writes the reply.
func fakeBridge(t *testing.T, path string, status int, reply map[string]any, capture *map[string]any) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		if capture != nil {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			*capture = body
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSendEncodesRequestAndDecodesResponse(t *testing.T) {
	rawResp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	var captured map[string]any
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusOK, map[string]any{
		"sent":            1,
		"status_code":     200,
		"response_base64": base64.StdEncoding.EncodeToString([]byte(rawResp)),
		"response_length": len(rawResp),
		"elapsed_ms":      42,
		"http_mode":       "HTTP_1",
	}, &captured)

	req := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	res, err := client.Send(context.Background(), "https://acme.test/x", "", req, SendOptions{Mode: HTTPModeHTTP1})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Sent || res.StatusCode != 200 || string(res.RawResponse) != rawResp || res.ElapsedMs != 42 {
		t.Fatalf("result = %+v", res)
	}
	if captured["http_mode"] != "http1" || captured["input_mode"] != "burp_base64" {
		t.Fatalf("request args = %+v", captured)
	}
	if captured["http_request_base64"] != base64.StdEncoding.EncodeToString(req) {
		t.Fatalf("request not base64-encoded: %+v", captured)
	}
}

func TestSendScopeBlockedReturnsTypedError(t *testing.T) {
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusForbidden, map[string]any{
		"error": "target is out of Burp scope; disable in-scope-only or add it to Target scope",
	}, nil)

	req := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	_, err := client.Send(context.Background(), "https://acme.test/x", "", req, SendOptions{})
	if !errors.Is(err, ErrScopeBlocked) {
		t.Fatalf("want ErrScopeBlocked, got %v", err)
	}
}

func TestSendTargetFailureIsNotAGoError(t *testing.T) {
	// A target-side failure returns HTTP 200 with sent:0 + error so per-request
	// outcomes stay uniform when fuzzing.
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusOK, map[string]any{
		"sent":  0,
		"error": "connection refused",
	}, nil)

	req := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	res, err := client.Send(context.Background(), "https://acme.test/x", "", req, SendOptions{})
	if err != nil {
		t.Fatalf("target failure must not be a Go error, got %v", err)
	}
	if res.Sent || res.Error != "connection refused" {
		t.Fatalf("result = %+v", res)
	}
}

func TestSendRequiresURLOrRef(t *testing.T) {
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusOK, map[string]any{"sent": 1}, nil)
	if _, err := client.Send(context.Background(), "", "", []byte("GET / HTTP/1.1\r\n\r\n"), SendOptions{}); err == nil {
		t.Fatal("expected error when neither url nor ref is supplied")
	}
	// A ref alone is valid (no url/request needed).
	if _, err := client.Send(context.Background(), "", "burp:abc", nil, SendOptions{}); err != nil {
		t.Fatalf("ref-only send should be valid: %v", err)
	}
}

func TestSendToRepeaterRateLimited(t *testing.T) {
	client := fakeBridge(t, "/api/burp-bridge/repeater", http.StatusTooManyRequests, map[string]any{
		"error": "Repeater send limit reached (30 per minute); retry shortly",
	}, nil)

	req := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	_, err := client.SendToRepeater(context.Background(), "https://acme.test/x", "", req, RepeaterOptions{TabName: "t"})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
}

func TestSendToOrganizerEncodesNotesAndResponse(t *testing.T) {
	var captured map[string]any
	client := fakeBridge(t, "/api/burp-bridge/organizer", http.StatusOK, map[string]any{
		"added": 1, "has_response": true, "notes": "recon-1",
	}, &captured)

	req := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	res, err := client.SendToOrganizer(context.Background(), "https://acme.test/x", "", req, resp, OrganizerOptions{
		Notes: "recon-1", Highlight: "Red",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || !res.HasResponse {
		t.Fatalf("result = %+v", res)
	}
	if captured["notes"] != "recon-1" || captured["highlight"] != "red" {
		t.Fatalf("request args = %+v", captured)
	}
	if captured["http_response_base64"] != base64.StdEncoding.EncodeToString(resp) {
		t.Fatalf("response not encoded: %+v", captured)
	}
}

func TestParseHTTPMode(t *testing.T) {
	cases := map[string]HTTPMode{
		"":                  HTTPModeAuto,
		"auto":              HTTPModeAuto,
		"http1":             HTTPModeHTTP1,
		"HTTP/1.1":          HTTPModeHTTP1,
		"http2":             HTTPModeHTTP2,
		"http2_ignore_alpn": HTTPModeHTTP2IgnoreALPN,
	}
	for in, want := range cases {
		got, err := ParseHTTPMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseHTTPMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseHTTPMode("http3"); err == nil {
		t.Fatal("expected error for unknown http mode")
	}
}

func TestSummaryFromSendMapsResponse(t *testing.T) {
	raw := []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nhello")
	sum := SummaryFromSend(SendResult{StatusCode: 404, RawResponse: raw, ElapsedMs: 12}, 0)
	if sum.Status != 404 || sum.ResponseLen != 5 || string(sum.RawBody) != "hello" || sum.ResponseTimeMs != 12 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.ContentHash == "" {
		t.Fatal("expected a content hash")
	}
	// A target-side failure carries only the error.
	failed := SummaryFromSend(SendResult{Error: "timeout", ElapsedMs: 30}, 0)
	if failed.Error != "timeout" || failed.Status != 0 {
		t.Fatalf("failed summary = %+v", failed)
	}
}

func TestBridgeSenderRoundTrips(t *testing.T) {
	rawResp := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nboo"
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusOK, map[string]any{
		"sent":            1,
		"status_code":     500,
		"response_base64": base64.StdEncoding.EncodeToString([]byte(rawResp)),
		"response_length": len(rawResp),
	}, nil)

	send := BridgeSender(client, "https", "acme.test", 443, SendOptions{}, 0)
	sum := send(context.Background(), []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n"))
	if sum.Status != 500 || string(sum.RawBody) != "boo" {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestBridgeSenderSurfacesErrorAsSummary(t *testing.T) {
	// A scope block must come back as a Summary error, not a panic, so a fuzz
	// loop keeps going.
	client := fakeBridge(t, "/api/burp-bridge/send", http.StatusForbidden, map[string]any{"error": "out of scope"}, nil)
	send := BridgeSender(client, "https", "acme.test", 443, SendOptions{}, 0)
	sum := send(context.Background(), []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n"))
	if sum.Error == "" {
		t.Fatalf("expected an error summary, got %+v", sum)
	}
}

func TestHealthParsesInScopeOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "vigolium-burp-bridge", "in_scope_only": true,
			"repeater_tabs_per_minute": 30,
		})
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.InScopeOnly || info.Service != "vigolium-burp-bridge" || info.RepeaterTabsPerMinute != 30 {
		t.Fatalf("health = %+v", info)
	}
}

// buildTargetURL shares replay.Authority with the native send path, so both
// senders name the same destination: default ports dropped, others kept, and
// an IPv6 host bracketed.
func TestBuildTargetURL(t *testing.T) {
	cases := []struct {
		scheme, host string
		port         int
		want         string
	}{
		{"https", "acme.test", 443, "https://acme.test"},
		{"http", "acme.test", 80, "http://acme.test"},
		{"", "acme.test", 0, "http://acme.test"},
		{"http", "127.0.0.1", 13313, "http://127.0.0.1:13313"},
		{"https", "::1", 8443, "https://[::1]:8443"},
		{"http", "::1", 80, "http://[::1]"},
	}
	for _, tc := range cases {
		if got := buildTargetURL(tc.scheme, tc.host, tc.port); got != tc.want {
			t.Errorf("buildTargetURL(%q, %q, %d) = %q, want %q", tc.scheme, tc.host, tc.port, got, tc.want)
		}
	}
}
