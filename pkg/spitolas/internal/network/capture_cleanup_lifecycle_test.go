package network

import (
	"testing"
	"time"
)

// TestCleanupLoopStopsOnlyOnCaptureClose pins the half of B03 that lives in this
// package: cleanupLoop's sole exit condition is c.stopped, and c.stopped is set
// by exactly one thing — Capture.Close.
//
// That matters because it is easy to assume closing the browser winds the
// capture down. It does not: ending CDP event delivery stops events arriving,
// but this loop is a timer, not an event consumer, so it keeps polling and keeps
// the whole Capture (pending/seen/logged maps included) reachable. ProbeURL used
// to close only the writer, and stranded one of these per captured probe.
func TestCleanupLoopStopsOnlyOnCaptureClose(t *testing.T) {
	c := New(NopWriter{}, true, true, false, false, false, "example.com", "test")

	done := make(chan struct{})
	go func() {
		c.cleanupLoop()
		close(done)
	}()

	// The loop must NOT exit on its own while the capture is live.
	select {
	case <-done:
		t.Fatal("cleanupLoop returned without Close; its exit condition changed")
	case <-time.After(250 * time.Millisecond):
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// cleanupLoop polls c.stopped every 100ms, so a second is ample headroom.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanupLoop did not return after Capture.Close; the goroutine leaks " +
			"for the life of the process")
	}
}

// TestCaptureCloseIsIdempotent covers the probe path calling Close on a capture
// whose browser has already gone away, and any caller that closes twice.
func TestCaptureCloseIsIdempotent(t *testing.T) {
	c := New(NopWriter{}, true, true, false, false, false, "example.com", "test")

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
