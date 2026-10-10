package browser

import (
	"context"
	"errors"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// neverRepaints stands in for rod's Page.WaitRepaint on a tab that stopped
// rendering: it blocks without looking at the element's context, exactly as
// the real wait (an Eval on rod's root page handle) does. It records the
// context it was handed so the test can check what a late repaint would meet.
func neverRepaints(release <-chan struct{}, got chan<- context.Context) func(*rod.Element) error {
	return func(el *rod.Element) error {
		got <- el.GetContext()
		<-release
		return nil
	}
}

func repaintTestElement(ctx context.Context, timeout time.Duration) *Element {
	return &Element{
		rodElem: (&rod.Element{}).Context(ctx),
		page:    &Page{config: &config.Config{ElementTimeout: timeout}},
	}
}

// TestRepaintOpReturnsOnCrawlCancel: a click waiting for a repaint that never
// comes must return as soon as the crawl context is cancelled, not when the
// tab closes.
func TestRepaintOpReturnsOnCrawlCancel(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	got := make(chan context.Context, 1)

	crawlCtx, cancel := context.WithCancel(context.Background())
	e := repaintTestElement(crawlCtx, time.Minute)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- e.repaintOp("Click", neverRepaints(release, got)) }()

	bound := <-got
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("returned after %v, want prompt return on cancel", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("repaintOp still blocked 5s after the crawl context was cancelled")
	}

	// The abandoned op's element is bound to a finished context, so a repaint
	// that turns up later fails its next CDP call instead of clicking.
	if bound.Err() == nil {
		t.Fatal("abandoned op's element context is still live")
	}
}

// TestRepaintOpTimesOutWithoutRepaint: with the crawl still running, the op is
// capped at ElementTimeout and reports a deadline, so the action fails and the
// crawl moves on.
func TestRepaintOpTimesOutWithoutRepaint(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	got := make(chan context.Context, 1)

	e := repaintTestElement(context.Background(), 100*time.Millisecond)

	start := time.Now()
	err := e.repaintOp("Hover", neverRepaints(release, got))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("returned after %v, want ~100ms", elapsed)
	}
}

// TestRepaintOpPassesThroughResultAndPanics: a normal op's result is returned
// as is, and a rod panic in the op's goroutine becomes an error rather than
// crashing the scan.
func TestRepaintOpPassesThroughResultAndPanics(t *testing.T) {
	e := repaintTestElement(context.Background(), time.Second)

	want := errors.New("not interactable")
	if err := e.repaintOp("Click", func(*rod.Element) error { return want }); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if err := e.repaintOp("Click", func(*rod.Element) error { return nil }); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if err := e.repaintOp("Click", func(*rod.Element) error { panic("nil frame") }); err == nil {
		t.Fatal("panic in op was not turned into an error")
	}

	// A zero element (nil context) still gets a bound.
	var nilCtx context.Context
	if err := runRepaintBounded(nilCtx, 50*time.Millisecond, "Focus", &rod.Element{}, func(el *rod.Element) error {
		<-el.GetContext().Done()
		return nil
	}); err == nil {
		t.Fatal("nil-context op was not bounded")
	}
}

// TestElementRepaintOpsGoThroughRepaintOp is a structural guard: element.go
// must not call a rod element method that scrolls into view (and so waits for a
// repaint) except through repaintOp.
func TestElementRepaintOpsGoThroughRepaintOp(t *testing.T) {
	src, err := os.ReadFile("element.go")
	if err != nil {
		t.Fatal(err)
	}
	bad := regexp.MustCompile(`(boundedElem\(\)|rodElem(\.Timeout\([^)]*\))?)\.(Click|Hover|Focus|Input|InputTime|InputColor|Select|SelectText|SelectAllText|ScrollIntoView|WaitInteractable|WaitStableRAF|Tap|Type|KeyActions|Screenshot)\(`)
	if m := bad.FindAll(src, -1); len(m) > 0 {
		t.Fatalf("repaint-waiting rod calls outside repaintOp: %q", m)
	}
}
