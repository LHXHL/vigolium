package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"golang.org/x/time/rate"
)

func gateMiddleware(g *egress.Gate) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return g.RoundTripper(next, egress.LaneNormal)
	}
}

// The egress hook sits INSIDE the retry middleware: a request the engine retries
// twice is three admissions, three counted attempts.
func TestEngineEgressAdmitsEachRetry(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // retryable status
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gate := egress.New(egress.Config{})
	var counted atomic.Int64
	cfg := testConfig(srv.URL)
	cfg.Engine.Egress = gateMiddleware(gate)
	cfg.Engine.RequestCounter = &counted
	if got := len(engineMiddleware(&cfg.Engine)); got != 3 {
		t.Fatalf("chain has %d rungs, want 3 (retry, egress, counting)", got)
	}

	engine, err := testEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer engine.Stop()

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/x", nil)
	rc, err := engine.httpClient.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	rc.Close()
	if gate.Sent() != 3 || counted.Load() != 3 {
		t.Fatalf("gate admitted %d, counter %d; want 3/3 (each retry admitted)", gate.Sent(), counted.Load())
	}
}

// One gate shared by two engines (two discovery targets in flight) paces them
// together: the discovery rate is phase-wide, not per target. Also shares the
// scan's host slots.
func TestEngineEgressRateIsGlobalAcrossTargets(t *testing.T) {
	var hits atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
	srvA := httptest.NewServer(handler)
	defer srvA.Close()
	srvB := httptest.NewServer(handler)
	defer srvB.Close()

	hosts := ratelimit.NewHostRateLimiter(ratelimit.DefaultHostRateLimiterConfig())
	defer func() { _ = hosts.Close() }()
	// 5 rps, burst 1: 11 requests need at least 10 × 200ms.
	gate := egress.New(egress.Config{Hosts: hosts}).WithRate(rate.NewLimiter(5, 1))

	engines := make([]*Engine, 0, 2)
	for _, u := range []string{srvA.URL, srvB.URL} {
		cfg := testConfig(u)
		cfg.Engine.Egress = gateMiddleware(gate)
		e, err := testEngineWithConfig(cfg)
		if err != nil {
			t.Fatalf("create engine: %v", err)
		}
		defer e.Stop()
		engines = append(engines, e)
	}

	const total = 11
	start := time.Now()
	var wg sync.WaitGroup
	var next atomic.Int64
	for i, e := range engines {
		base := []string{srvA.URL, srvB.URL}[i]
		wg.Add(1)
		go func(e *Engine, base string) {
			defer wg.Done()
			for next.Add(1) <= total {
				req, _ := http.NewRequestWithContext(context.Background(), "GET", base+"/x", nil)
				rc, err := e.httpClient.Send(context.Background(), req)
				if err != nil {
					t.Errorf("send: %v", err)
					return
				}
				rc.Close()
			}
		}(e, base)
	}
	wg.Wait()

	if elapsed := time.Since(start); elapsed < 1800*time.Millisecond {
		t.Fatalf("%d requests across two targets at 5/s took %v; want >= ~2s (the bucket is per target)", total, elapsed)
	}
	if gate.Sent() != total || hits.Load() != total {
		t.Fatalf("gate sent %d, server hits %d; want %d", gate.Sent(), hits.Load(), total)
	}
}
