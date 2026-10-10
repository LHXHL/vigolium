package ratelimit

import (
	"context"
	"testing"
	"time"
)

// AcquirePriority takes a normal slot when one is free, the reserved slot when
// none is, and otherwise waits — in both the static and the adaptive entry
// shapes. The reserved slot keeps the entry busy for eviction.
func TestAcquirePriority(t *testing.T) {
	for _, adaptive := range []bool{false, true} {
		name := "static"
		if adaptive {
			name = "adaptive"
		}
		t.Run(name, func(t *testing.T) {
			cfg := DefaultHostRateLimiterConfig()
			cfg.MaxPerHost = 1
			cfg.Adaptive = adaptive
			cfg.AcquireTimeout = 2 * time.Second
			h := NewHostRateLimiter(cfg)
			defer func() { _ = h.Close() }()
			ctx := context.Background()

			first, err := h.AcquirePriority(ctx, "a.test")
			if err != nil {
				t.Fatal(err)
			}
			// The normal slot is gone; a normal acquire must wait.
			short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()
			if err := h.Acquire(short, "a.test"); err == nil {
				t.Fatal("first priority acquire should have taken the normal slot")
			}

			second, err := h.AcquirePriority(ctx, "a.test")
			if err != nil {
				t.Fatalf("priority acquire with the normal slot held: %v", err)
			}
			shard := h.shardFor("a.test")
			shard.mu.RLock()
			entry := shard.hosts["a.test"]
			shard.mu.RUnlock()
			if len(entry.reserved) != 1 || !entry.hasInflight() {
				t.Fatal("second priority acquire should hold the reserved slot")
			}

			third := make(chan error, 1)
			go func() {
				rel, err := h.AcquirePriority(ctx, "a.test")
				if err == nil {
					rel()
				}
				third <- err
			}()
			select {
			case err := <-third:
				t.Fatalf("third priority acquire did not wait (err=%v)", err)
			case <-time.After(50 * time.Millisecond):
			}
			second()
			if err := <-third; err != nil {
				t.Fatal(err)
			}
			first()
			if len(entry.reserved) != 0 || entry.hasInflight() {
				t.Fatal("slots not returned")
			}
			if err := h.AcquireWithTimeoutContext(ctx, "a.test"); err != nil {
				t.Fatalf("normal slot not returned by a priority release: %v", err)
			}
			h.Release("a.test")
		})
	}
}
