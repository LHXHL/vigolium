package runner

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// These guard the spidering watchdog — the hard guarantee that a wedged RunSpider
// (unresponsive/anti-bot browser, an unbounded rod CDP call, a stuck teardown)
// can never hang the scan forever. runWithWatchdog is the testable core;
// runSpiderWatchdog wraps it around the real (browser-driven) RunSpider.
//
// The second return value, `wedged`, is what the phases use to decide whether a
// shared browser session can still be closed. A wedge must be abandoned (closing
// an unresponsive browser hangs the phase the watchdog protects); an ordinary
// crawl failure must NOT be, because the browser is healthy and its record
// writer still holds that host's captured traffic. Conflating the two leaked a
// Chrome process per host group and discarded records earlier seeds had already
// produced — so every case below asserts `wedged`, not just the result.

// TestRunWithWatchdog_FastWorkReturnsResult: work that finishes before the
// timeout returns its own result and is not wedged; onTimeout is never called.
func TestRunWithWatchdog_FastWorkReturnsResult(t *testing.T) {
	var onTimeoutCalled bool
	got, wedged := runWithWatchdog(
		2*time.Second,
		func() string { return "work" },
		func() string { onTimeoutCalled = true; return "timeout" },
	)
	if got != "work" {
		t.Fatalf("got %q, want %q", got, "work")
	}
	if wedged {
		t.Error("work that finished in time must not be reported as wedged")
	}
	if onTimeoutCalled {
		t.Fatal("onTimeout was called even though work finished in time")
	}
}

// TestRunWithWatchdog_FailedWorkIsNotWedged is the distinction the phases turn
// on: BOTH the worker's own failure and a watchdog timeout produce a non-nil
// error, so an error-only signature would make them indistinguishable at exactly
// the point where the difference decides whether a browser gets closed.
func TestRunWithWatchdog_FailedWorkIsNotWedged(t *testing.T) {
	ordinary := errors.New("net::ERR_CONNECTION_REFUSED")

	got, wedged := runWithWatchdog(
		2*time.Second,
		func() error { return ordinary },
		func() error { return errors.New("timed out") },
	)
	if wedged {
		t.Error("a crawl that returned its own error must not be reported as wedged — " +
			"the browser is healthy and its writer still holds captured records")
	}
	if !errors.Is(got, ordinary) {
		t.Errorf("got %v, want the worker's own error", got)
	}
}

// TestRunWithWatchdog_WedgedWorkTimesOut: work that blocks past the timeout does
// NOT hang the caller — onTimeout's result is returned promptly with wedged
// true, within a small multiple of the timeout (proving the wedged worker is
// abandoned, not awaited).
func TestRunWithWatchdog_WedgedWorkTimesOut(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // let the abandoned worker exit at test end

	const timeout = 100 * time.Millisecond
	start := time.Now()
	got, wedged := runWithWatchdog(
		timeout,
		func() string {
			<-release // simulate a wedged op that never returns on its own
			return "work"
		},
		func() string { return "timeout" },
	)
	elapsed := time.Since(start)

	if got != "timeout" {
		t.Fatalf("got %q, want %q (watchdog should have fired)", got, "timeout")
	}
	if !wedged {
		t.Error("a watchdog timeout must be reported as wedged, or the phase will " +
			"try to close a browser that is not answering")
	}
	// Must return ~at the timeout, not block on the wedged worker. Generous upper
	// bound to stay non-flaky on loaded CI.
	if elapsed > 2*time.Second {
		t.Fatalf("runWithWatchdog blocked %s on a wedged worker; the watchdog did not abandon it", elapsed)
	}
}

// TestRunWithWatchdog_LateWorkerDoesNotBlock: after the watchdog fires and the
// caller has moved on, the abandoned worker finishing later must not panic or
// deadlock on the (buffered) done channel.
func TestRunWithWatchdog_LateWorkerDoesNotBlock(t *testing.T) {
	finished := make(chan struct{})
	var once sync.Once

	got, wedged := runWithWatchdog(
		50*time.Millisecond,
		func() int {
			time.Sleep(300 * time.Millisecond) // finishes well after the watchdog fired
			once.Do(func() { close(finished) })
			return 1
		},
		func() int { return -1 },
	)
	if got != -1 || !wedged {
		t.Fatalf("got (%d, %v), want (-1, true) — the timeout path", got, wedged)
	}

	// The late worker must complete cleanly (buffered send, no deadlock/panic).
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("abandoned worker never finished — it likely blocked sending on the done channel")
	}
}

// TestCrawlOutcomeCarriesWedgedSeparatelyFromErr documents the struct contract
// the two watchdog wrappers return, since `wedged` is not derivable from `err`.
func TestCrawlOutcomeCarriesWedgedSeparatelyFromErr(t *testing.T) {
	ordinary := crawlOutcome{err: errors.New("navigation failed")}
	if ordinary.wedged {
		t.Error("a crawl that returned an error is not wedged by default")
	}

	timedOut := crawlOutcome{err: errors.New("timed out"), wedged: true}
	if !timedOut.wedged {
		t.Error("wedged must survive alongside err")
	}
}
