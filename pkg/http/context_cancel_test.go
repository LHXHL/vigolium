package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestWithContext_CancelsInFlightExecute proves that a context bound via
// WithContext aborts an in-flight context-less Execute — the mechanism the
// executor relies on to cancel legacy active modules at their per-module
// timeout. Without WithContext, Execute waits for the slow server.
func TestWithContext_CancelsInFlightExecute(t *testing.T) {
	opts := types.DefaultOptions()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts}
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}

	// Server holds the connection open well past the bound below.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(800 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, execErr := r.WithContext(ctx).Execute(rr, Options{NoClustering: true})
	elapsed := time.Since(start)

	if execErr == nil {
		t.Fatal("expected Execute to fail when the bound context is cancelled")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Execute did not honour the bound context: took %s (cancel at 150ms, server sleeps 800ms)", elapsed)
	}
}

// TestExecute_QuarantinedHostSkipsLimiterAcquire proves the quarantine check
// runs BEFORE the per-host limiter acquire: a request to an unresponsive host
// returns immediately even when the host's only limiter slot is occupied,
// rather than blocking on a slot it would never use.
func TestExecute_QuarantinedHostSkipsLimiterAcquire(t *testing.T) {
	opts := types.DefaultOptions()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}

	// One slot per host with a long acquire timeout: an acquire-first ordering
	// would block ~5s on the saturated slot, blowing the sub-second bound below.
	limiter := ratelimit.NewHostRateLimiter(ratelimit.HostRateLimiterConfig{
		MaxPerHost:     1,
		EvictInterval:  time.Hour,
		AcquireTimeout: 5 * time.Second,
	})
	defer func() { _ = limiter.Close() }()

	// MaxHostError 1 + tracked "boom" substring: a single MarkFailed quarantines.
	hostErrors := hosterrors.New(1, 100, []string{"boom"})
	defer hostErrors.Close()

	svc := &services.Services{Options: opts, HostLimiter: limiter, HostErrors: hostErrors}
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}

	rr, err := httpmsg.GetRawRequestFromURL("http://127.0.0.1:9/")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	hostErrors.MarkFailed(httpmsg.HostPortKey(rr), errors.New("boom"), false)
	if !hostErrors.Quarantined(httpmsg.HostPortKey(rr)) {
		t.Fatal("precondition: request's host should be quarantined")
	}
	// Saturate the host's single limiter slot.
	if err := limiter.Acquire(context.Background(), rr.Service().Host()); err != nil {
		t.Fatalf("saturate slot: %v", err)
	}

	start := time.Now()
	_, _, execErr := r.Execute(rr, Options{NoClustering: true})
	elapsed := time.Since(start)

	if !errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
		t.Fatalf("Execute err = %v, want ErrUnresponsiveHost", execErr)
	}
	if elapsed > time.Second {
		t.Errorf("quarantine check did not short-circuit before the limiter acquire: took %s (slot full, 5s acquire timeout)", elapsed)
	}
}

func TestWithContext_NilReturnsReceiver(t *testing.T) {
	r := &Requester{}
	// Deliberately exercise the documented nil-context path; use a typed nil so
	// staticcheck (SA1012) doesn't flag the intentional nil literal.
	var nilCtx context.Context
	if r.WithContext(nilCtx) != r {
		t.Error("WithContext(nil) should return the receiver unchanged")
	}
	bound := r.WithContext(context.Background())
	if bound == r {
		t.Error("WithContext(ctx) should return a distinct copy")
	}
	if bound.defaultCtx == nil {
		t.Error("WithContext(ctx) should set defaultCtx")
	}
}
