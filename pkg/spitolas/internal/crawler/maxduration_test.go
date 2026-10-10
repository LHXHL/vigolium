package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// newTestCrawler builds a crawler with the given max duration. New() does not
// launch a browser (that happens in Run), so this is a pure in-memory unit.
func newTestCrawler(t *testing.T, maxDuration time.Duration) *Crawler {
	t.Helper()
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.MaxDuration = maxDuration
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestShouldTerminateMaxDuration is the regression guard for the spidering
// timeout overrun: shouldTerminate must honor MaxDuration as an in-engine
// backstop, independent of the context deadline. Before the fix MaxDuration was
// dead config — shouldTerminate only checked ctx.Done(), MaxStates, and
// MaxConsecutiveFails — so a caller that set MaxDuration but passed a
// deadline-less context would never stop on time.
func TestShouldTerminateMaxDuration(t *testing.T) {
	tests := []struct {
		name        string
		maxDuration time.Duration
		startOffset time.Duration // how long ago the crawl "started" (0 = not started)
		want        bool
	}{
		{
			name:        "elapsed past max duration terminates",
			maxDuration: 5 * time.Minute,
			startOffset: 10 * time.Minute,
			want:        true,
		},
		{
			name:        "elapsed exactly at max duration terminates",
			maxDuration: 5 * time.Minute,
			startOffset: 5 * time.Minute,
			want:        true,
		},
		{
			name:        "within budget keeps going",
			maxDuration: 5 * time.Minute,
			startOffset: 1 * time.Minute,
			want:        false,
		},
		{
			name:        "unlimited (zero) never terminates on duration",
			maxDuration: 0,
			startOffset: 24 * time.Hour,
			want:        false,
		},
		{
			name:        "not started yet does not terminate",
			maxDuration: 5 * time.Minute,
			startOffset: 0, // StartTime stays zero
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCrawler(t, tt.maxDuration)
			if tt.startOffset > 0 {
				c.stats.StartTime = time.Now().Add(-tt.startOffset)
			}

			// Use a never-cancelled context so we isolate the MaxDuration leg
			// from the ctx.Done() leg.
			if got := c.shouldTerminate(context.Background()); got != tt.want {
				t.Fatalf("shouldTerminate() = %v, want %v (maxDuration=%s, startOffset=%s)",
					got, tt.want, tt.maxDuration, tt.startOffset)
			}
		})
	}
}

// TestShouldTerminateContextCancel confirms the existing context-cancellation
// leg still wins regardless of the duration budget — the caller's deadline is
// the primary stop signal; MaxDuration is the backstop.
func TestShouldTerminateContextCancel(t *testing.T) {
	c := newTestCrawler(t, time.Hour) // generous budget, well within it
	c.stats.StartTime = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if !c.shouldTerminate(ctx) {
		t.Fatal("shouldTerminate() = false with a cancelled context, want true")
	}
}

// TestShouldTerminateDrainGrace: inside DrainGrace of the deadline — the
// context's or MaxDuration's — the crawl schedules no new state, so in-flight
// work drains inside the budget; outside it, the crawl continues.
func TestShouldTerminateDrainGrace(t *testing.T) {
	t.Run("context deadline within grace stops", func(t *testing.T) {
		c := newTestCrawler(t, 0)
		c.config.DrainGrace = 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if !c.shouldTerminate(ctx) {
			t.Fatal("5s left with a 10s grace: want terminate")
		}
	})
	t.Run("context deadline beyond grace continues", func(t *testing.T) {
		c := newTestCrawler(t, 0)
		c.config.DrainGrace = 10 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if c.shouldTerminate(ctx) {
			t.Fatal("a minute left with a 10s grace: want continue")
		}
	})
	t.Run("max duration minus grace stops", func(t *testing.T) {
		c := newTestCrawler(t, time.Minute)
		c.config.DrainGrace = 10 * time.Second
		c.stats.StartTime = time.Now().Add(-55 * time.Second)
		if !c.shouldTerminate(context.Background()) {
			t.Fatal("55s into a 1m budget with a 10s grace: want terminate")
		}
	})
	t.Run("no grace runs to the deadline", func(t *testing.T) {
		c := newTestCrawler(t, time.Minute)
		c.stats.StartTime = time.Now().Add(-55 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if c.shouldTerminate(ctx) {
			t.Fatal("without a grace the crawl runs to its deadline")
		}
	})
}
