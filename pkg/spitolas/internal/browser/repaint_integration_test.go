//go:build integration && (linux || darwin)

package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClickOnHiddenTabReturnsOnCrawlCancel launches a real headless browser.
// Run with:
//
//	go test -tags=integration -run TestClickOnHiddenTab ./pkg/spitolas/internal/browser/...
//
// A tab hidden behind another tab of its window stops rendering, so the
// requestAnimationFrame that rod's click waits on (scroll-into-view →
// Page.WaitRepaint) never fires. That wait ignores every context but the tab's
// own, so before repaintOp the click blocked until the tab closed, long past a
// cancelled crawl. Now it must return promptly once the crawl context ends.
func TestClickOnHiddenTabReturnsOnCrawlCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><button id="b">go</button></body></html>`))
	}))
	t.Cleanup(srv.Close)

	b := newHeadlessBrowser(t, srv.URL)
	b.config.ElementTimeout = time.Minute // only the crawl cancel can end the wait

	crawlCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.SetCrawlContext(crawlCtx)

	hidden, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := hidden.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	elem, err := hidden.Element("#b")
	if err != nil {
		t.Fatalf("Element: %v", err)
	}

	// A second tab in the same window hides the first.
	front, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage (front): %v", err)
	}
	if err := front.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate (front): %v", err)
	}
	if v, err := hidden.RodPage().Eval(`() => document.visibilityState`); err == nil && v.Value.Str() != "hidden" {
		t.Skipf("first tab is %q, not hidden, in this Chrome; no repaint stall to test", v.Value.Str())
	}

	done := make(chan error, 1)
	go func() { done <- elem.Click() }()

	// Give the click time to reach the repaint wait, then end the crawl.
	select {
	case err := <-done:
		t.Skipf("click on the hidden tab finished without stalling (err=%v); no repaint stall to test", err)
	case <-time.After(1 * time.Second):
	}
	start := time.Now()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Click err = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("Click returned %v after cancel, want prompt", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Click on a hidden tab still blocked 10s after the crawl context was cancelled")
	}
}
