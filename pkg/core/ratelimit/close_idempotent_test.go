package ratelimit

import (
	"sync"
	"testing"
)

// TestCloseIsIdempotent guards against "close of closed channel", which panics
// the whole process rather than returning an error. A shared limiter can have
// several closers: a phase that borrows one closes it on its own defer, as does
// the owner.
func TestCloseIsIdempotent(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{})
	if err := h.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Concurrent closers must not race into a double close either.
func TestCloseIsSafeUnderConcurrency(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Close()
		}()
	}
	wg.Wait()
}
