package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// TestScopeRejectedPreSend: every item refused by the pre-send scope check is
// counted, so a run whose whole input was out of scope is distinguishable from
// one that scanned everything and found nothing.
func TestScopeRejectedPreSend(t *testing.T) {
	t.Parallel()
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	e, _ := newTestExecutor(ExecutorConfig{
		Workers:      1,
		ScopeMatcher: config.NewScopeMatcher(scopeCfg),
	}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}

	const n = 5
	items := make([]*work.WorkItem, 0, n)
	for i := 0; i < n; i++ {
		item, _ := makeTestItem(fmt.Sprintf("h%d.example.com", i), "/", "<html>x</html>")
		items = append(items, item)
	}
	e.source = &sliceSource{items: items}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := e.ScopeRejected(); got != n {
		t.Errorf("ScopeRejected() = %d, want %d", got, n)
	}
	rep := e.Report()
	if rep.ScopeRejected != n || rep.Responded != 0 {
		t.Errorf("Report() = %+v, want ScopeRejected=%d Responded=0", rep, n)
	}
	if !rep.Clean() {
		t.Errorf("scope rejection is not a coverage gap; Report() = %+v should be clean", rep)
	}

	// A second run on the same executor reports only its own share, while the
	// accessor stays cumulative.
	more, _ := makeTestItem("again.example.com", "/", "<html>x</html>")
	e.source = &sliceSource{items: []*work.WorkItem{more}}
	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("second Execute() error = %v", err)
	}
	if rep := e.Report(); rep.ScopeRejected != 1 {
		t.Errorf("second run Report().ScopeRejected = %d, want 1", rep.ScopeRejected)
	}
	if got := e.ScopeRejected(); got != n+1 {
		t.Errorf("cumulative ScopeRejected() = %d, want %d", got, n+1)
	}
}

// TestScopeRejectedPostFetch: an item that passes the request-only check but
// fails a response-side rule (here the status code) is counted after the fetch.
func TestScopeRejectedPostFetch(t *testing.T) {
	t.Parallel()
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.StatusCode = config.ScopeRule{Include: []string{"404"}}
	scopeCfg.IgnoreStaticFile = false
	e, _ := newTestExecutor(ExecutorConfig{ScopeMatcher: config.NewScopeMatcher(scopeCfg)}, nil)
	e.scanCtx = &modules.ScanContext{}

	item, _ := makeTestItem("example.com", "/page", "<html>x</html>") // 200 response
	e.processItem(context.Background(), item)

	if got := e.ScopeRejected(); got != 1 {
		t.Errorf("ScopeRejected() = %d, want 1", got)
	}
	if got := e.Responded(); got != 1 {
		t.Errorf("Responded() = %d, want 1 (the baseline answered before scope refused it)", got)
	}

	// An in-scope item is not counted.
	inScope, _ := makeTestItem("example.com", "/ok", "<html>x</html>")
	scopeCfg.StatusCode = config.ScopeRule{Include: []string{"*"}}
	e.cfg.ScopeMatcher = config.NewScopeMatcher(scopeCfg)
	e.processItem(context.Background(), inScope)
	if got := e.ScopeRejected(); got != 1 {
		t.Errorf("ScopeRejected() after in-scope item = %d, want 1", got)
	}
}
