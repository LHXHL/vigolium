//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// historySPA serves a history-API single-page app whose /reports/:id view —
// and the XHR it makes — exists only in the bundle's router: no link, form,
// sitemap or inline string points at it. Every unknown path falls back to the
// app shell, as a history-mode SPA server does.
func historySPA(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var reportXHR atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`(function () {
  var el = document.getElementById('app');
  var path = location.pathname;
  var m = /^\/rep(?:o)rts\/([^\/]+)$/.exec(path);
  if (m) {
    fetch('/api/report-' + 'data?id=' + encodeURIComponent(m[1]))
      .then(function (r) { return r.text(); })
      .then(function (t) { el.textContent = 'report ' + t; });
    return;
  }
  if (path === '/about') { el.innerHTML = '<h1>About</h1><a href="/">home</a>'; return; }
  el.innerHTML = '<h1>Home</h1><a href="/about">about</a>';
})();`))
		case "/api/report-data":
			reportXHR.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"report":"ROUTECANARY"}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><head><title>spa</title></head><body><div id="app"></div><script src="/static/app.js"></script></body></html>`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reportXHR
}

func runRouteSeedCrawl(t *testing.T, target string, seeds []SeedURL) (*SpiderResult, *memSink) {
	t.Helper()
	sink := &memSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := RunSpider(ctx, SpiderConfig{
		TargetURL: target, MaxStates: 6, MaxDepth: 2, MaxDuration: 40 * time.Second,
		Headless: true, IncludeResponseBody: true, IncludeHeaders: true,
		ExtraSeeds: seeds,
	}, sink)
	if err != nil {
		t.Fatalf("RunSpider: %v", err)
	}
	return res, sink
}

// TestExtraSeedReachesJSOnlyHistoryRoute: a client route handed in as an
// extra seed ("/reports/:id", as discovery's jstangle facts report it) is
// navigated as origin + concrete path, and the view's XHR is captured. Without
// the seed the crawl never reaches it.
func TestExtraSeedReachesJSOnlyHistoryRoute(t *testing.T) {
	srv, reportXHR := historySPA(t)

	runRouteSeedCrawl(t, srv.URL, nil)
	if reportXHR.Load() != 0 {
		t.Fatalf("control crawl reached the JS-only route (%d XHRs); the fixture no longer isolates it", reportXHR.Load())
	}

	res, sink := runRouteSeedCrawl(t, srv.URL, []SeedURL{{URL: "/reports/:id", Source: "jstangle-route", Priority: 1}})
	if res.ExtraSeedsAccepted != 1 || res.ExtraSeedsCrawled != 1 {
		t.Errorf("extra seeds accepted/crawled = %d/%d, want 1/1", res.ExtraSeedsAccepted, res.ExtraSeedsCrawled)
	}
	if reportXHR.Load() == 0 {
		t.Fatal("the route seed never triggered the view's XHR")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var sawDoc, sawXHR bool
	for _, rr := range sink.records {
		if rr.Request() == nil {
			continue
		}
		p := rr.Request().Path()
		sawDoc = sawDoc || p == "/reports/1"
		sawXHR = sawXHR || strings.HasPrefix(p, "/api/report-data")
	}
	if !sawDoc || !sawXHR {
		t.Errorf("captured route document=%v, route XHR=%v; want both", sawDoc, sawXHR)
	}
}
