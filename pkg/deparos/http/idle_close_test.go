package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// connTracker counts how many server-side connections are currently open. The
// assertion this test cares about is server-observed, not a transport internal:
// whether the socket actually went away, not whether we called a method.
type connTracker struct {
	mu   sync.Mutex
	open int
}

func (c *connTracker) stateHook(_ net.Conn, s http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch s {
	case http.StateNew:
		c.open++
	case http.StateClosed, http.StateHijacked:
		c.open--
	}
}

func (c *connTracker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open
}

// waitForOpen polls until the tracker reports want (or fails). The server closes
// its side asynchronously, so an immediate read races the close.
func (c *connTracker) waitForOpen(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("open connections = %d, want %d", c.count(), want)
}

func TestClientCloseIdleConnectionsReleasesSockets(t *testing.T) {
	tracker := &connTracker{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = tracker.stateHook
	srv.Start()
	defer srv.Close()

	// Retry middleware in the chain: this is the configuration the discovery
	// engine actually builds, and it is the one that used to swallow the
	// idle-close entirely.
	client := NewClient(&ClientConfig{
		PoolConfig: DefaultPoolConfig(),
		Middleware: []Middleware{RetryMiddleware(DefaultRetryConfig())},
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	chain, err := client.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := chain.Fill(); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	chain.Close()

	// The connection is now idle in the pool, not closed: keep-alive is the
	// point. If this is already 0 the test proves nothing about the fix.
	tracker.waitForOpen(t, 1)

	client.CloseIdleConnections()
	tracker.waitForOpen(t, 0)
}

func TestClientCloseIdleConnectionsIsSafeToRepeat(t *testing.T) {
	client := NewClient(nil)
	client.CloseIdleConnections()
	client.CloseIdleConnections()

	var nilClient *Client
	nilClient.CloseIdleConnections() // must not panic
}

// TestMiddlewareChainForwardsCloseIdleConnections pins the chain contract: a
// caller holding the bare client from HTTPClient() must still be able to close
// idle connections. One middleware without the method swallows the call for
// everything beneath it, so this covers the FULL stack, not just retry.
func TestMiddlewareChainForwardsCloseIdleConnections(t *testing.T) {
	middlewares := map[string]Middleware{
		"retry":     RetryMiddleware(DefaultRetryConfig()),
		"ratelimit": RateLimitMiddleware(DefaultRateLimitConfig()),
	}

	for name, mw := range middlewares {
		t.Run(name, func(t *testing.T) {
			inner := &idleCloseRecorder{}
			closer, ok := mw(inner).(interface{ CloseIdleConnections() })
			if !ok {
				t.Fatalf("%s middleware does not implement CloseIdleConnections, so it breaks the chain", name)
			}
			closer.CloseIdleConnections()
			if !inner.closed {
				t.Errorf("%s did not forward the idle close to the wrapped transport", name)
			}
		})
	}

	// And the whole stack together, in the order NewClient applies it.
	inner := &idleCloseRecorder{}
	var rt http.RoundTripper = inner
	for _, mw := range []Middleware{
		RateLimitMiddleware(DefaultRateLimitConfig()),
		RetryMiddleware(DefaultRetryConfig()),
	} {
		rt = mw(rt)
	}
	closer, ok := rt.(interface{ CloseIdleConnections() })
	if !ok {
		t.Fatal("the middleware chain does not implement CloseIdleConnections")
	}
	closer.CloseIdleConnections()
	if !inner.closed {
		t.Error("idle close did not reach the base transport through the full chain")
	}
}

// idleCloseRecorder is a RoundTripper that records whether the idle-close
// reached it through the middleware chain.
type idleCloseRecorder struct {
	closed bool
}

func (i *idleCloseRecorder) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("idleCloseRecorder does not serve requests")
}

func (i *idleCloseRecorder) CloseIdleConnections() { i.closed = true }
