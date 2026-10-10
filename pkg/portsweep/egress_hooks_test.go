package portsweep

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type countingRT struct {
	next http.RoundTripper
	n    *atomic.Int64
}

func (c countingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.next.RoundTrip(r)
}

// The confirm step goes through WrapTransport (the scan's egress gate) and every
// TCP pre-filter dial is reported through OnDial, open port or not.
func TestSweep_EgressHooks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	var wrapped, dials atomic.Int64
	opts := fastOpts([]int{portOf(t, srv.URL), closed})
	opts.WrapTransport = func(next http.RoundTripper) http.RoundTripper { return countingRT{next: next, n: &wrapped} }
	opts.OnDial = func() { dials.Add(1) }

	res := Sweep(context.Background(), "127.0.0.1", opts)
	if len(res.Open) != 1 {
		t.Fatalf("open = %+v, want the one live port", res.Open)
	}
	if dials.Load() != 2 {
		t.Fatalf("OnDial called %d times, want 2 (one per probed port)", dials.Load())
	}
	if wrapped.Load() < 1 {
		t.Fatal("the confirm request did not go through WrapTransport")
	}
}
