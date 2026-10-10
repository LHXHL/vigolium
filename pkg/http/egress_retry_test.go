package http

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"golang.org/x/time/rate"
)

// flakyServer drops the connection (no response) for the first `drops`
// requests, then answers 200.
func flakyServer(t *testing.T, drops int64, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= drops {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server does not support hijacking")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newGatedRequester(t *testing.T, retries int, lim *rate.Limiter) (*Requester, *egress.Gate) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Retries = retries
	opts.Timeout = 3 * time.Second
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts, RateLimiter: lim}
	svc.Egress = egress.New(egress.Config{Rate: lim})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	r.retryBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(r.CloseIdleConnections)
	return r, svc.Egress
}

// Retries run through the gate: each wire attempt pays a token and is counted,
// on the requester and on the scan-wide gate alike.
func TestRequester_RetryEachAttemptGated(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 2, &hits)
	lim := rate.NewLimiter(rate.Every(time.Hour), 3) // three tokens, no refill
	r, gate := newGatedRequester(t, 2, lim)

	in, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := r.Execute(in, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("Execute after two dropped attempts: %v", err)
	}
	resp.Close()

	if hits.Load() != 3 {
		t.Fatalf("server saw %d attempts, want 3", hits.Load())
	}
	if r.RequestsSent() != 3 || gate.Sent() != 3 {
		t.Fatalf("requester sent=%d gate sent=%d, want 3/3", r.RequestsSent(), gate.Sent())
	}
	if lim.Tokens() > 0.01 {
		t.Fatalf("%.2f tokens left: a retry went out without a token", lim.Tokens())
	}
}

// Out of retries, the error says how many attempts were made (the message
// retryablehttp used to produce), and still classifies as a transport error.
func TestRequester_RetryExhausted(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 100, &hits)
	r, _ := newGatedRequester(t, 1, nil)

	in, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = r.Execute(in, Options{NoClustering: true})
	if err == nil {
		t.Fatal("expected an error")
	}
	if hits.Load() != 2 {
		t.Fatalf("server saw %d attempts, want 2 (1 + 1 retry)", hits.Load())
	}
	if class := ClassifyTransportError(err); class != TransportErrReset {
		t.Fatalf("ClassifyTransportError(%v) = %q, want reset", err, class)
	}
}

// A raw request is one round trip by design and is never retried.
func TestRequester_RawRequestNotRetried(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 100, &hits)
	r, _ := newGatedRequester(t, 3, nil)

	in, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Execute(in, Options{NoClustering: true, RawRequest: true}); err == nil {
		t.Fatal("expected an error")
	}
	if hits.Load() != 1 {
		t.Fatalf("raw request sent %d times, want 1", hits.Load())
	}
}

// A request whose URL cannot be built (path-normalization's "..;/" with no
// leading slash glues onto the port) fails identically on every attempt, so it
// is not retried: each retry used to cost a backoff sleep per malformed probe.
func TestRequester_BuildErrorNotRetried(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 0, &hits)
	r, gate := newGatedRequester(t, 3, nil)

	in, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := httpmsg.SetPath(in.Request().Raw(), "..;/..;/")
	if err != nil {
		t.Fatal(err)
	}
	bad := httpmsg.NewRequestResponseRaw(raw, in.Service())
	if _, _, err := r.Execute(bad, Options{NoClustering: true}); err == nil {
		t.Fatal("expected a build error")
	}
	if gate.Sent() != 1 {
		t.Fatalf("gate admitted %d attempts, want 1 (no retries of a build error)", gate.Sent())
	}
	if hits.Load() != 0 {
		t.Fatalf("server saw %d requests, want 0", hits.Load())
	}
}

// A followed redirect hop is another wire attempt: it takes a token and counts.
func TestRequester_RedirectHopTakesToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lim := rate.NewLimiter(rate.Every(time.Hour), 2)
	r, gate := newGatedRequester(t, 0, lim)
	in, err := httpmsg.GetRawRequestFromURL(srv.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := r.Execute(in, Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()
	if resp.Response().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the followed 200", resp.Response().StatusCode)
	}
	if r.RequestsSent() != 2 || gate.Sent() != 2 {
		t.Fatalf("requester sent=%d gate sent=%d, want 2/2 (request + hop)", r.RequestsSent(), gate.Sent())
	}
	if lim.Tokens() > 0.01 {
		t.Fatal("the redirect hop did not take a token")
	}
}

// A module's own dial is admitted and counted through the requester's gate.
func TestRequester_AcquireDial(t *testing.T) {
	r, gate := newGatedRequester(t, 0, nil)
	release, err := r.AcquireDial("a.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if gate.Sent() != 1 {
		t.Fatalf("gate sent = %d, want 1", gate.Sent())
	}
	var nilReq *Requester
	if rel, err := nilReq.AcquireDial("a.test", 443); err != nil || rel == nil {
		t.Fatal("nil requester must admit")
	}
}

// A requester built on Services whose components differ from Services.Egress
// (the probe phase swaps in its own limiter) applies the new components but
// still counts into the scan-wide gate.
func TestRequester_DerivedGateSharesCounter(t *testing.T) {
	opts := types.DefaultOptions()
	opts.Retries = 0
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	scanGate := egress.New(egress.Config{})
	local := &services.Services{Options: opts, Egress: scanGate, RateLimiter: rate.NewLimiter(rate.Inf, 1)}
	r, err := NewRequester(opts, local)
	if err != nil {
		t.Fatal(err)
	}
	defer r.CloseIdleConnections()
	if r.Gate() == scanGate {
		t.Fatal("requester should get a view over its own rate limiter")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	in, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	resp, _, err := r.Execute(in, Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if scanGate.Sent() != 1 {
		t.Fatalf("scan gate sent = %d, want 1", scanGate.Sent())
	}
}
