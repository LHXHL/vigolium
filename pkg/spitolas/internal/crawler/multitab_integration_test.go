//go:build integration

package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

// treeSite serves a static 30-state application: an index linking to five
// sections, each linking to its leaves (5,5,5,5,4) and back home. Every page
// renders a distinct DOM, so the reachable state set is exactly its 30 URLs.
// pageDelay slows every page but the index, so tabs have work to overlap.
func treeSite(t *testing.T, pageDelay time.Duration) (*httptest.Server, []string) {
	t.Helper()
	leaves := []int{5, 5, 5, 5, 4}
	paths := []string{"/"}
	pages := map[string]string{}

	var idx strings.Builder
	idx.WriteString("<h1>Index</h1><ul>")
	for s, n := range leaves {
		sp := fmt.Sprintf("/s%d", s)
		paths = append(paths, sp)
		fmt.Fprintf(&idx, `<li><a href="%s">Section %d</a></li>`, sp, s)

		var sec strings.Builder
		fmt.Fprintf(&sec, `<h1>Section %d</h1><a href="/">Home</a><ul>`, s)
		for l := 0; l < n; l++ {
			lp := fmt.Sprintf("/s%d/l%d", s, l)
			paths = append(paths, lp)
			fmt.Fprintf(&sec, `<li><a href="%s">Leaf %d-%d</a></li>`, lp, s, l)
			pages[lp] = fmt.Sprintf(`<h1>Leaf %d-%d</h1><p>leaf body %d %d</p><a href="/">Home</a>`, s, l, s, l)
		}
		sec.WriteString("</ul>")
		pages[sp] = sec.String()
	}
	idx.WriteString("</ul>")
	pages["/"] = idx.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/" && pageDelay > 0 {
			select {
			case <-time.After(pageDelay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body>%s</body></html>", r.URL.Path, body)
	}))
	t.Cleanup(srv.Close)

	urls := make([]string, len(paths))
	for i, p := range paths {
		urls[i] = srv.URL + p
	}
	return srv, urls
}

func multitabConfig(t *testing.T, target string, tabs int) *config.Config {
	t.Helper()
	cfg, err := config.New(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headless = true
	cfg.Tabs = tabs
	cfg.MaxDepth = 4
	cfg.MaxDuration = 150 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond
	cfg.DOMStableTime = 200 * time.Millisecond
	// Keep the comparison to the multi-consumer loop itself.
	cfg.FollowUpPasses = 0
	cfg.SeedFromRobots = false
	cfg.SeedFromSitemap = false
	return cfg
}

type crawlOutcome struct {
	urls     []string
	ids      []string
	duration time.Duration
	stats    Stats
}

func runTreeCrawl(t *testing.T, target string, tabs int) crawlOutcome {
	t.Helper()
	c, err := New(multitabConfig(t, target, tabs))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	start := time.Now()
	res, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("tabs=%d: crawl failed: %v", tabs, err)
	}
	out := crawlOutcome{duration: time.Since(start), stats: res.Stats}

	seenURL := map[string]bool{}
	for _, s := range res.Graph.AllStates() {
		u := strings.TrimSuffix(s.URL, "/")
		if seenURL[u] {
			t.Errorf("tabs=%d: duplicate state for %s", tabs, s.URL)
		}
		seenURL[u] = true
		out.urls = append(out.urls, u)
		out.ids = append(out.ids, s.ID)
	}
	sort.Strings(out.urls)
	sort.Strings(out.ids)
	if got := res.Stats.StatesDiscovered; got != res.StateCount() {
		t.Errorf("tabs=%d: StatesDiscovered=%d but the graph has %d states (a state counted twice?)", tabs, got, res.StateCount())
	}
	return out
}

// TestMultiTabCrawlMatchesSingleTab: three tabs reach exactly the state set one
// tab does — same URLs, same stripped-DOM hashes — with no duplicate state,
// and finish sooner. Run under -race this also exercises every shared
// component (graph, candidates, fragment manager, MAB policy, form dedup).
func TestMultiTabCrawlMatchesSingleTab(t *testing.T) {
	_, urls := treeSite(t, 150*time.Millisecond)
	want := make([]string, len(urls))
	for i, u := range urls {
		want[i] = strings.TrimSuffix(u, "/")
	}
	sort.Strings(want)

	one := runTreeCrawl(t, urls[0], 1)
	three := runTreeCrawl(t, urls[0], 3)
	t.Logf("tabs=1: %d states in %s; tabs=3: %d states in %s",
		len(one.urls), one.duration, len(three.urls), three.duration)

	if !slices.Equal(one.urls, want) {
		t.Errorf("tabs=1 reached %v\nwant %v", one.urls, want)
	}
	if !slices.Equal(three.urls, one.urls) {
		t.Errorf("tabs=3 reached %v\ntabs=1 reached %v", three.urls, one.urls)
	}
	if !slices.Equal(three.ids, one.ids) {
		t.Errorf("tabs=3 state IDs differ from tabs=1:\n%v\n%v", three.ids, one.ids)
	}
	if three.duration >= one.duration {
		t.Errorf("tabs=3 took %s, not less than tabs=1's %s", three.duration, one.duration)
	}
}

// TestMultiTabIsolatedContexts: the context-isolation mode crawls the same
// application to the same state set.
func TestMultiTabIsolatedContexts(t *testing.T) {
	_, urls := treeSite(t, 0)
	cfg := multitabConfig(t, urls[0], 2)
	cfg.TabIsolation = config.TabIsolationContext
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	res, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("crawl failed: %v", err)
	}
	if got := res.StateCount(); got != len(urls) {
		t.Errorf("isolated tabs reached %d states, want %d", got, len(urls))
	}
}

// TestMultiTabCancellationClosesTabs: cancelling mid-crawl returns promptly
// and closes every extra tab (on a session-owned browser, which outlives the
// crawl, so the closed tabs can be checked).
func TestMultiTabCancellationClosesTabs(t *testing.T) {
	_, urls := treeSite(t, 2*time.Second)
	cfg := multitabConfig(t, urls[0], 3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := browser.NewPoolWithContext(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	br := pool.Get()
	capture := network.New(network.NopWriter{}, true, true, false, false, false, cfg.URL.Hostname(), "spider")
	if err := capture.Start(br.RodBrowser()); err != nil {
		t.Fatal(err)
	}
	defer capture.Close()

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	type runResult struct {
		res *Result
		err error
	}
	done := make(chan runResult, 1)
	go func() {
		res, err := c.RunOnBrowser(ctx, br, capture)
		done <- runResult{res, err}
	}()

	// Wait for the extra tabs, then for them to be mid-navigation.
	var tabTargets []proto.TargetTargetID
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if pages := c.extraTabPages(); len(pages) == 2 {
			for _, p := range pages {
				tabTargets = append(tabTargets, p.RodPage().TargetID)
			}
			break
		}
		select {
		case r := <-done:
			t.Fatalf("crawl ended before its tabs opened: %v", r.err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if len(tabTargets) != 2 {
		t.Fatal("extra tabs never opened")
	}
	time.Sleep(3 * time.Second)

	cancel()
	cancelled := time.Now()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("RunOnBrowser did not return within 6s of cancellation")
	}
	t.Logf("returned %s after cancel", time.Since(cancelled))

	open, err := br.RodBrowser().Pages()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range open {
		if slices.Contains(tabTargets, p.TargetID) {
			t.Errorf("extra tab %s still open after the crawl returned", p.TargetID)
		}
	}
	if left := c.extraTabPages(); len(left) != 0 {
		t.Errorf("%d extra tabs still tracked", len(left))
	}
}
