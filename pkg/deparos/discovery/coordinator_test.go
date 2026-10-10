package discovery

import (
	"context"
	"fmt"
	"hash/fnv"
	stdhttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/testutil"
	"github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/goleak"
)

// createMockCallbacks creates callbacks with mock HTTP client and analyzer
func createMockCallbacks() *Callbacks {
	reqCache, _ := reqcache.NewHMapCache(&reqcache.Config{Cleanup: true})
	return &Callbacks{
		HTTPClient:   testutil.NewMockHTTPClient(),
		Analyzer:     http.NewAnalyzer(nil), // Use real analyzer with nil comparator
		RequestCache: reqCache,
	}
}

func TestPayloadCoordinator_IdleState(t *testing.T) {
	queue := queue.New()
	coordinator := NewPayloadCoordinator(queue, 2, createMockCallbacks())

	// Initially idle
	if !coordinator.IsIdle() {
		t.Error("expected coordinator to be idle initially")
	}

	if coordinator.CurrentTask() != nil {
		t.Error("expected no current task initially")
	}
}

// stubExpandTask is a minimal expandable task with a configurable priority and
// URL list. When gate is set, Expand blocks (honouring ctx) before its first
// item, which lets a test hold an expansion open with no work in flight.
type stubExpandTask struct {
	name     string
	priority uint8
	urls     []string
	gate     <-chan struct{}
}

func (s *stubExpandTask) Hash() uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s.name))
	return h.Sum64()
}
func (s *stubExpandTask) Priority() uint8                   { return s.priority }
func (s *stubExpandTask) Description() string               { return "stub " + s.name }
func (s *stubExpandTask) FoundByName() string               { return "fuzzer" }
func (s *stubExpandTask) PayloadProvider() payload.Provider { return nil }
func (s *stubExpandTask) FullURL() []byte                   { return []byte("http://example.test/") }
func (s *stubExpandTask) Extension() string                 { return "" }
func (s *stubExpandTask) Depth() uint16                     { return 0 }
func (s *stubExpandTask) IsFromSpider() bool                { return false }
func (s *stubExpandTask) Expand(ctx context.Context, cb func(url string, depth uint16)) error {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, u := range s.urls {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		cb(u, 0)
	}
	return nil
}

func stubURLs(prefix string, n int) []string {
	urls := make([]string, n)
	for i := range urls {
		urls[i] = fmt.Sprintf("http://example.test/%s-%d", prefix, i)
	}
	return urls
}

// coordinatorHarness runs a PayloadCoordinator against a recording mock client.
type coordinatorHarness struct {
	t      *testing.T
	q      *queue.TaskQueue
	c      *PayloadCoordinator
	client *testutil.MockHTTPClient
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	counts map[string]int // sends per URL path prefix (text before the last '-')
	onSend func(path string, nth int)
}

func newCoordinatorHarness(t *testing.T, workers int) *coordinatorHarness {
	t.Helper()
	reqCache, err := reqcache.NewHMapCache(&reqcache.Config{Path: t.TempDir(), Cleanup: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reqCache.Close() })

	h := &coordinatorHarness{t: t, q: queue.New(), client: testutil.NewMockHTTPClient(),
		counts: map[string]int{}, done: make(chan struct{})}
	h.client.ResponseFunc = func(req *stdhttp.Request) (*responsechain.ResponseChain, error) {
		path := req.URL.Path
		prefix := path
		if i := strings.LastIndexByte(path, '-'); i > 0 {
			prefix = path[:i]
		}
		h.mu.Lock()
		h.counts[prefix]++
		nth := h.counts[prefix]
		onSend := h.onSend
		h.mu.Unlock()
		if onSend != nil {
			onSend(prefix, nth)
		}
		return testutil.NewMockResponseChain(404, "Not Found"), nil
	}
	h.c = NewPayloadCoordinator(h.q, workers, &Callbacks{
		HTTPClient:   h.client,
		Analyzer:     http.NewAnalyzer(nil),
		RequestCache: reqCache,
	})
	return h
}

func (h *coordinatorHarness) setOnSend(fn func(path string, nth int)) {
	h.mu.Lock()
	h.onSend = fn
	h.mu.Unlock()
}

func (h *coordinatorHarness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		_ = h.c.Run(ctx)
	}()
}

// stop cancels the coordinator and waits for Run to return.
func (h *coordinatorHarness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Fatal("coordinator Run did not return after cancel")
	}
}

// waitQuiescent waits until want requests were sent, the queue is empty and the
// coordinator idle. The request count guards against the instant between a
// Dequeue and its accounting, which the engine covers with a 2s idle window.
func (h *coordinatorHarness) waitQuiescent(want int) {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		return int(h.client.RequestCount.Load()) >= want && h.q.IsEmpty() && h.c.IsIdle()
	}, 30*time.Second, 5*time.Millisecond, "coordinator never became idle")
}

// sentPaths returns request paths in send order.
func (h *coordinatorHarness) sentPaths() []string {
	reqs := h.client.GetRequests()
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.URL.Path
	}
	return out
}

// countBefore counts requests whose path has prefix, sent before the first
// request whose path equals target. It fails the test when target was never sent.
func countBefore(t *testing.T, paths []string, prefix, target string) int {
	t.Helper()
	n := 0
	for _, p := range paths {
		if p == target {
			return n
		}
		if strings.HasPrefix(p, prefix) {
			n++
		}
	}
	t.Fatalf("%s was never sent", target)
	return 0
}

func lastIndexWithPrefix(paths []string, prefix string) int {
	last := -1
	for i, p := range paths {
		if strings.HasPrefix(p, prefix) {
			last = i
		}
	}
	return last
}

// assertEachSentOnce asserts every URL in want was sent exactly once.
func assertEachSentOnce(t *testing.T, paths []string, want []string) {
	t.Helper()
	seen := make(map[string]int, len(paths))
	for _, p := range paths {
		seen[p]++
	}
	for _, u := range want {
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		if seen[parsed.Path] != 1 {
			t.Fatalf("%s sent %d times, want 1", parsed.Path, seen[parsed.Path])
		}
	}
}

// TestPayloadCoordinator_JSReplayNotStarvedByFuzz pins the §3.8 contract: a JS
// replay queued while a 10k-item fuzz expansion is running is sent within a few
// hundred fuzz items rather than after all of them, and no fuzz item is lost.
func TestPayloadCoordinator_JSReplayNotStarvedByFuzz(t *testing.T) {
	verifyNoLeaks(t)

	h := newCoordinatorHarness(t, 4)
	words := make([]string, 10000)
	for i := range words {
		words[i] = fmt.Sprintf("fuzz-%d", i)
	}
	h.q.Enqueue(NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: "http://example.test/" + fuzzMarker,
		Provider:    payload.NewMockProvider(words...),
	}))
	dir, _ := url.Parse("http://example.test/")
	replay := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL: dir,
		GetExtractedRequests: func() []jstangle.ExtractedRequest {
			return []jstangle.ExtractedRequest{{Method: "GET", URL: "/api/replayed"}}
		},
	})
	h.setOnSend(func(prefix string, nth int) {
		if prefix == "/fuzz" && nth == 100 {
			h.q.Enqueue(replay)
		}
	})

	h.start()
	h.waitQuiescent(10001)
	h.stop()

	paths := h.sentPaths()
	require.Len(t, paths, 10001, "every fuzz item plus the replay must be sent")
	before := countBefore(t, paths, "/fuzz-", "/api/replayed")
	assert.Less(t, before, 300, "JS replay must be sent before fuzz item 300")
	assert.GreaterOrEqual(t, before, 100)
	assertEachSentOnce(t, paths, stubURLs("fuzz", 10000))
	assert.Equal(t, int32(0), h.c.Metrics().InlineInFlight.Load())
	assert.Equal(t, int32(0), h.c.Metrics().ExpansionsInFlight.Load())
}

// TestPayloadCoordinator_NestedPreemptionResumes covers the suspended stack: a
// band-1 task preempts a band-2 fuzz, a band-0 task preempts that, and both
// suspended expansions resume most-urgent-first with no item lost.
func TestPayloadCoordinator_NestedPreemptionResumes(t *testing.T) {
	verifyNoLeaks(t)

	h := newCoordinatorHarness(t, 4)
	low := &stubExpandTask{name: "low", priority: PriorityFuzzer, urls: stubURLs("low", 2000)}
	mid := &stubExpandTask{name: "mid", priority: PriorityShortDirs, urls: stubURLs("mid", 500)}
	high := &stubExpandTask{name: "high", priority: PrioritySpider, urls: stubURLs("high", 50)}
	h.q.Enqueue(low)
	h.setOnSend(func(prefix string, nth int) {
		switch {
		case prefix == "/low" && nth == 100:
			h.q.Enqueue(mid)
		case prefix == "/mid" && nth == 100:
			h.q.Enqueue(high)
		}
	})

	h.start()
	h.waitQuiescent(2550)
	h.stop()

	paths := h.sentPaths()
	require.Len(t, paths, 2550)
	assertEachSentOnce(t, paths, append(append(stubURLs("low", 2000), stubURLs("mid", 500)...), stubURLs("high", 50)...))
	assert.Less(t, countBefore(t, paths, "/low-", "/mid-0"), 300, "mid must preempt low")
	assert.Less(t, countBefore(t, paths, "/mid-", "/high-0"), 300, "high must preempt mid")
	lastHigh, lastMid, lastLow := lastIndexWithPrefix(paths, "/high-"), lastIndexWithPrefix(paths, "/mid-"), lastIndexWithPrefix(paths, "/low-")
	assert.Less(t, lastHigh, lastMid, "high must finish before suspended mid resumes to completion")
	assert.Less(t, lastMid, lastLow, "mid must finish before suspended low resumes to completion")

	m := h.c.Metrics()
	assert.Equal(t, uint64(2), m.Preemptions.Load())
	assert.Equal(t, int32(0), m.SuspendedExpansions.Load())
	assert.Equal(t, int32(0), m.ExpansionsInFlight.Load())
	assert.Equal(t, uint64(3), m.TasksCompleted.Load())
}

// TestPayloadCoordinator_SameBandDoesNotPreempt keeps equal-band tasks in FIFO
// expansion order: preemption needs a strictly more urgent band.
func TestPayloadCoordinator_SameBandDoesNotPreempt(t *testing.T) {
	verifyNoLeaks(t)

	// One worker, so send order is exactly expansion order.
	h := newCoordinatorHarness(t, 1)
	first := &stubExpandTask{name: "first", priority: PriorityLongFilesNoExt, urls: stubURLs("first", 1000)}
	second := &stubExpandTask{name: "second", priority: PriorityFuzzer, urls: stubURLs("second", 10)}
	h.q.Enqueue(first)
	h.setOnSend(func(prefix string, nth int) {
		if prefix == "/first" && nth == 10 {
			h.q.Enqueue(second)
		}
	})

	h.start()
	h.waitQuiescent(1010)
	h.stop()

	paths := h.sentPaths()
	require.Len(t, paths, 1010)
	assert.Equal(t, 1000, countBefore(t, paths, "/first-", "/second-0"))
	assert.Equal(t, uint64(0), h.c.Metrics().Preemptions.Load())
}

// TestPayloadCoordinator_SuspendedExpansionBlocksQuiescence asserts IsIdle stays
// false while an expansion is suspended, even with the queue empty and every
// worker idle, and that the suspended expansion completes once resumed.
func TestPayloadCoordinator_SuspendedExpansionBlocksQuiescence(t *testing.T) {
	verifyNoLeaks(t)

	h := newCoordinatorHarness(t, 2)
	gate := make(chan struct{})
	low := &stubExpandTask{name: "low", priority: PriorityFuzzer, urls: stubURLs("low", 500)}
	blocked := &stubExpandTask{name: "blocked", priority: PrioritySpider, urls: stubURLs("blocked", 5), gate: gate}
	h.q.Enqueue(low)
	h.setOnSend(func(prefix string, nth int) {
		if prefix == "/low" && nth == 10 {
			h.q.Enqueue(blocked)
		}
	})

	h.start()
	m := h.c.Metrics()
	require.Eventually(t, func() bool {
		return m.SuspendedExpansions.Load() == 1 && h.q.IsEmpty() &&
			m.InFlightItems.Load() == 0 && len(h.c.workChan) == 0
	}, 10*time.Second, time.Millisecond, "low never got suspended behind the blocked task")

	for i := 0; i < 20; i++ {
		require.False(t, h.c.IsIdle(), "a suspended expansion must keep the coordinator busy")
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, int32(2), m.ExpansionsInFlight.Load())

	close(gate)
	h.waitQuiescent(505)
	h.stop()

	paths := h.sentPaths()
	require.Len(t, paths, 505)
	assertEachSentOnce(t, paths, append(stubURLs("low", 500), stubURLs("blocked", 5)...))
	assert.Equal(t, int32(0), m.SuspendedExpansions.Load())
	assert.Equal(t, int32(0), m.ExpansionsInFlight.Load())
}

// TestPayloadCoordinator_CancelWithSuspendedExpansionsNoLeak cancels the run
// while one expansion is suspended and another is blocked inside Expand: Run
// must return, every producer goroutine must exit and the accounting must reset.
func TestPayloadCoordinator_CancelWithSuspendedExpansionsNoLeak(t *testing.T) {
	verifyNoLeaks(t)

	h := newCoordinatorHarness(t, 2)
	low := &stubExpandTask{name: "low", priority: PriorityFuzzer, urls: stubURLs("low", 5000)}
	blocked := &stubExpandTask{name: "blocked", priority: PrioritySpider, urls: stubURLs("blocked", 5), gate: make(chan struct{})}
	h.q.Enqueue(low)
	h.setOnSend(func(prefix string, nth int) {
		if prefix == "/low" && nth == 10 {
			h.q.Enqueue(blocked)
		}
	})

	h.start()
	m := h.c.Metrics()
	require.Eventually(t, func() bool { return m.SuspendedExpansions.Load() == 1 },
		10*time.Second, time.Millisecond)

	h.stop()
	assert.Equal(t, int32(0), m.SuspendedExpansions.Load())
	assert.Equal(t, int32(0), m.ExpansionsInFlight.Load())
	assert.Less(t, len(h.sentPaths()), 5000, "cancel must abandon the suspended expansion")
}

func TestPriorityBand(t *testing.T) {
	cases := map[uint8]int{
		PrioritySpider: 0, PriorityJSExtractedRequest: 0,
		PriorityObservedDirs: 1, PriorityShortDirs: 1, PriorityNumericFuzz: 1,
		PriorityLongFilesNoExt: 2, PriorityMalformedPathProbe: 2, PriorityFuzzer: 2,
	}
	for p, want := range cases {
		assert.Equal(t, want, priorityBand(p), "priority %d", p)
	}
}

// verifyNoLeaks checks for leaked goroutines after every other cleanup (the
// request cache's LevelDB goroutines stop in a t.Cleanup registered later;
// LevelDB's memory-pool drainer exits on its own ticker after Close).
func verifyNoLeaks(t *testing.T) {
	t.Helper()
	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() {
		goleak.VerifyNone(t, ignore,
			goleak.IgnoreTopFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mpoolDrain"))
	})
}
