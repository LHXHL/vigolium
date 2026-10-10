package source

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// concurrencyProbe records how many fake targets ran at once, overall and per
// host:port key.
type concurrencyProbe struct {
	mu        sync.Mutex
	now       int
	peak      int
	perKey    map[string]int
	peakByKey map[string]int
	threads   map[string]int
}

func newConcurrencyProbe() *concurrencyProbe {
	return &concurrencyProbe{perKey: map[string]int{}, peakByKey: map[string]int{}, threads: map[string]int{}}
}

func (p *concurrencyProbe) enter(ctx context.Context, target string) {
	key := discoveryHostKey(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now++
	p.peak = max(p.peak, p.now)
	p.perKey[key]++
	p.peakByKey[key] = max(p.peakByKey[key], p.perKey[key])
	p.threads[target] = targetThreads(ctx, -1)
}

func (p *concurrencyProbe) leave(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now--
	p.perKey[discoveryHostKey(target)]--
}

// sleepingTargets is a discoverFn that holds each target for d.
func (p *concurrencyProbe) sleepingTargets(d time.Duration) func(context.Context, string) error {
	return func(ctx context.Context, target string) error {
		p.enter(ctx, target)
		defer p.leave(target)
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func drainToEOF(t *testing.T, d *DeparosDiscoverySource) {
	t.Helper()
	_, err := d.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
}

// TestRunDiscovery_ConcurrentTargetsWallTime: six targets on six hosts under
// the default pool of three take about two target-times, not six.
func TestRunDiscovery_ConcurrentTargetsWallTime(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const per = 150 * time.Millisecond
	targets := make([]string, 6)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://host%d.example/", i)
	}
	probe := newConcurrencyProbe()
	d := newLifecycleSource(t, context.Background(), targets, probe.sleepingTargets(per))
	t.Cleanup(func() { _ = d.Close() })

	start := time.Now()
	drainToEOF(t, d)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 2*per, "six targets three at a time is two rounds")
	assert.Less(t, elapsed, 4*per, "the pool must not run targets one at a time")
	assert.Equal(t, 3, probe.peak, "default pool width is min(len(targets), 3)")
	stats := d.Stats()
	assert.Zero(t, stats.TargetsSkipped)
	assert.Zero(t, stats.TargetsFailed)
}

// TestRunDiscovery_SameHostSerialized: two targets on one host:port never run
// together, even with pool slots free; other hosts run alongside them.
func TestRunDiscovery_SameHostSerialized(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	targets := []string{
		"http://a.example/one",
		"http://A.example:80/two", // same origin as the first
		"http://a.example/three",
		"https://a.example/", // a different port is a different origin
		"http://b.example/",
	}
	probe := newConcurrencyProbe()
	d := newLifecycleSource(t, context.Background(), targets, probe.sleepingTargets(60*time.Millisecond))
	d.cfg.TargetConcurrency = 4
	t.Cleanup(func() { _ = d.Close() })

	drainToEOF(t, d)

	assert.Equal(t, 1, probe.peakByKey["a.example:80"], "same host:port must be serialized")
	assert.Equal(t, 3, probe.peak, "a.example:80, a.example:443 and b.example run together")
	assert.Len(t, probe.threads, len(targets), "every target ran")
}

// TestRunDiscovery_CancelMidRunCountsSkipped: cancelling while a pool of two
// is busy stops both running targets (attempted, not failed) and reports every
// target that never started as skipped.
func TestRunDiscovery_CancelMidRunCountsSkipped(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := make([]string, 7)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://h%d.example/", i)
	}
	var calls atomic.Int32
	entered := make(chan struct{}, len(targets))
	d := newLifecycleSource(t, ctx, targets, func(innerCtx context.Context, _ string) error {
		calls.Add(1)
		entered <- struct{}{}
		<-innerCtx.Done()
		return innerCtx.Err()
	})
	d.cfg.TargetConcurrency = 2

	nextDone := make(chan error, 1)
	go func() {
		_, err := d.Next(context.Background())
		nextDone <- err
	}()
	<-entered
	<-entered
	cancel()

	select {
	case err := <-nextDone:
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("Next did not return after cancelling the source context")
	}
	require.NoError(t, d.Close())

	stats := d.Stats()
	assert.Equal(t, int32(2), calls.Load(), "only the two pooled targets may start")
	assert.Equal(t, 5, stats.TargetsSkipped, "every unstarted target is skipped")
	assert.Zero(t, stats.TargetsFailed, "a cancelled target is not a failed one")
}

// TestRunDiscovery_SplitsThreadsAcrossRunnableTargets: the engine thread budget
// is divided by the targets that can actually run together.
func TestRunDiscovery_SplitsThreadsAcrossRunnableTargets(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		total   int
		want    int
	}{
		{"three hosts share the budget", []string{"https://a.example/", "https://b.example/", "https://c.example/"}, 30, 10},
		{"one host keeps the whole budget", []string{"https://a.example/x", "https://a.example/y", "https://a.example/z"}, 30, 30},
		{"the share has a floor", []string{"https://a.example/", "https://b.example/", "https://c.example/"}, 9, 5},
		{"a single target is unsplit", []string{"https://a.example/"}, 30, 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := newConcurrencyProbe()
			d := newLifecycleSource(t, context.Background(), tc.targets, probe.sleepingTargets(time.Millisecond))
			d.cfg.Concurrency = tc.total
			t.Cleanup(func() { _ = d.Close() })
			drainToEOF(t, d)
			// The first dispatch sees every target pending; later ones may see
			// fewer. Only the first target is pinned.
			assert.Equal(t, tc.want, probe.threads[tc.targets[0]])
		})
	}
}

func TestDiscoveryHostKey(t *testing.T) {
	cases := map[string]string{
		"http://Example.com/a":      "example.com:80",
		"http://example.com:80/b":   "example.com:80",
		"https://example.com":       "example.com:443",
		"https://example.com:8443/": "example.com:8443",
		"not a url":                 "not a url",
	}
	for in, want := range cases {
		assert.Equal(t, want, discoveryHostKey(in), in)
	}
}

func TestTargetConcurrencyResolution(t *testing.T) {
	assert.Equal(t, 3, DeparosDiscoveryConfig{}.targetConcurrency(10))
	assert.Equal(t, 2, DeparosDiscoveryConfig{}.targetConcurrency(2))
	assert.Equal(t, 1, DeparosDiscoveryConfig{TargetConcurrency: 1}.targetConcurrency(10))
	assert.Equal(t, 4, DeparosDiscoveryConfig{TargetConcurrency: 8}.targetConcurrency(4))
	assert.Equal(t, 1, DeparosDiscoveryConfig{}.targetConcurrency(0))
}
