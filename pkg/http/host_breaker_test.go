package http

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

type breakerClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *breakerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *breakerClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newBreakerRequester(t *testing.T, cache *hosterrors.Cache) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Retries = 0
	opts.Timeout = 2 * time.Second
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r, err := NewRequester(opts, &services.Services{Options: opts, HostErrors: cache})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return r
}

// A refused GET quarantines the host:port for every method: the POST that
// follows is short-circuited without touching the network.
func TestRequester_GETFailureQuarantinesPOST(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens: connection refused

	cache := hosterrors.New(1, 100, nil)
	r := newBreakerRequester(t, cache)

	get, err := httpmsg.GetRawRequestFromURL("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Execute(get, Options{NoClustering: true}); err == nil {
		t.Fatal("GET to a closed port should fail")
	}
	if !cache.Quarantined(httpmsg.HostPortKey(get)) {
		t.Fatalf("host %s not quarantined after a refused GET", httpmsg.HostPortKey(get))
	}

	post := httpmsg.NewHttpRequestResponse(get.Request().WithMethod("POST"), nil)
	sentBefore := r.RequestsSent()
	_, _, err = r.Execute(post, Options{NoClustering: true})
	if !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		t.Fatalf("POST err = %v, want ErrUnresponsiveHost", err)
	}
	if r.RequestsSent() != sentBefore {
		t.Error("quarantined POST reached the network")
	}
}

// After the cooldown the requester's own send is the half-open probe; a
// success closes the breaker.
func TestRequester_HalfOpenProbeRecovers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clock := &breakerClock{t: time.Unix(1_700_000_000, 0)}
	cache := hosterrors.NewWithConfig(hosterrors.Config{
		MaxHostError: 1,
		TrackError:   []string{"boom"},
		Cooldown:     30 * time.Second,
		Now:          clock.Now,
	})
	r := newBreakerRequester(t, cache)

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	key := httpmsg.HostPortKey(rr)
	cache.MarkFailed(key, errors.New("boom"), false)

	if _, _, err := r.Execute(rr, Options{NoClustering: true}); !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		t.Fatalf("during cooldown err = %v, want ErrUnresponsiveHost", err)
	}

	clock.Advance(31 * time.Second)
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	resp.Close()
	if got := cache.State(key); got != hosterrors.StateClosed {
		t.Fatalf("state after successful probe = %s, want closed", got)
	}
}
