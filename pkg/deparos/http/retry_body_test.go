package http

import (
	"bytes"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fastRetryConfig is the production default with the backoff collapsed, so the
// retryable-status list keeps exactly one owner (DefaultRetryConfig) — restating
// it here would leave these tests green against a stale contract.
func fastRetryConfig(maxAttempts int) *RetryConfig {
	cfg := DefaultRetryConfig()
	cfg.MaxAttempts = maxAttempts
	cfg.InitialBackoff = time.Millisecond
	cfg.MaxBackoff = 2 * time.Millisecond
	return cfg
}

func roundTripVia(t *testing.T, cfg *RetryConfig, srv *httptest.Server, body io.Reader) (*nethttp.Response, error) {
	t.Helper()
	rt := RetryMiddleware(cfg)(nethttp.DefaultTransport)
	req, err := nethttp.NewRequest(nethttp.MethodGet, srv.URL, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return rt.RoundTrip(req)
}

// TestFinalRetryableResponseBodyIsReadable is the regression guard for the closed
// final response: the body was closed as soon as a retryable status was seen, even
// on the last attempt, so the caller got a 429/503 it could not read. Against a
// rate-limiting host that turned real throttling into silently empty responses.
func TestFinalRetryableResponseBodyIsReadable(t *testing.T) {
	const payload = "rate limited, slow down"
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.WriteHeader(nethttp.StatusTooManyRequests)
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	resp, err := roundTripVia(t, fastRetryConfig(2), srv, nil)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != nethttp.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the final retryable response failed: %v", err)
	}
	if string(got) != payload {
		t.Errorf("body = %q, want %q", got, payload)
	}
}

// A retryable status that later succeeds must still return the success body, and
// the intermediate response must not leak.
func TestRetryThenSuccessReturnsFinalBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(nethttp.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "try again")
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	resp, err := roundTripVia(t, fastRetryConfig(3), srv, nil)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
	if calls != 2 {
		t.Errorf("server saw %d calls, want 2", calls)
	}
}

// TestRetryReplaysRequestBody covers the other half of the clone bug: Clone does
// not duplicate the body stream, so without a GetBody replay the second attempt
// was sent with an empty body.
func TestRetryReplaysRequestBody(t *testing.T) {
	const payload = "name=value"
	var seen []string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		if len(seen) == 1 {
			w.WriteHeader(nethttp.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	// strings.Reader gives net/http a GetBody automatically.
	resp, err := roundTripVia(t, fastRetryConfig(3), srv, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if len(seen) != 2 {
		t.Fatalf("server saw %d attempts, want 2", len(seen))
	}
	for i, body := range seen {
		if body != payload {
			t.Errorf("attempt %d body = %q, want %q", i+1, body, payload)
		}
	}
}

// A body with no GetBody must not be retried and re-sent empty.
func TestRetrySkipsNonReplayableBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		calls++
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(nethttp.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rt := RetryMiddleware(fastRetryConfig(3))(nethttp.DefaultTransport)
	req, err := nethttp.NewRequest(nethttp.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// An opaque reader: net/http cannot synthesize GetBody for it.
	req.Body = io.NopCloser(bytes.NewBufferString("opaque"))
	req.GetBody = nil

	resp, err := rt.RoundTrip(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
	if calls != 1 {
		t.Errorf("server saw %d calls, want 1 (a non-replayable body must not be retried)", calls)
	}
}

// A misconfigured MaxAttempts must not produce the (nil, nil) that every
// RoundTripper caller treats as a protocol violation.
func TestZeroMaxAttemptsStillSendsOnce(t *testing.T) {
	var calls int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		calls++
		w.WriteHeader(nethttp.StatusOK)
	}))
	defer srv.Close()

	resp, err := roundTripVia(t, fastRetryConfig(0), srv, nil)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp == nil {
		t.Fatal("got (nil, nil) from RoundTrip")
	}
	_ = resp.Body.Close()
	if calls != 1 {
		t.Errorf("server saw %d calls, want 1", calls)
	}
}
