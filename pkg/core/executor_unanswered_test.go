package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// unansweredLog collects OnUnanswered calls.
type unansweredLog struct {
	mu      sync.Mutex
	reasons map[string]string // target -> reason
	errs    map[string]error
}

func (l *unansweredLog) note(item *work.WorkItem, reason string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reasons == nil {
		l.reasons, l.errs = map[string]string{}, map[string]error{}
	}
	l.reasons[item.Request.Target()] = reason
	l.errs[item.Request.Target()] = err
}

// TestOnUnansweredScopeRejected: an item refused by the pre-send scope check
// is reported with DropOutOfScope, once.
func TestOnUnansweredScopeRejected(t *testing.T) {
	t.Parallel()
	var log unansweredLog
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.Host = config.ScopeRule{Include: []string{"nomatch.example"}}
	e, _ := newTestExecutor(ExecutorConfig{
		Workers:      1,
		ScopeMatcher: config.NewScopeMatcher(scopeCfg),
		OnUnanswered: log.note,
	}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	item, _ := makeTestItem("out.example.com", "/", "<html>x</html>")
	e.source = &sliceSource{items: []*work.WorkItem{item}}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(log.reasons) != 1 {
		t.Fatalf("OnUnanswered calls = %v, want 1", log.reasons)
	}
	for _, reason := range log.reasons {
		if reason != DropOutOfScope {
			t.Errorf("reason = %q, want %q", reason, DropOutOfScope)
		}
	}
}

// TestOnUnansweredFetchError: a target whose port is closed is reported with
// DropFetchError and the transport error as the cause; an answered item is not
// reported at all.
func TestOnUnansweredFetchError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	var log unansweredLog
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1, OnUnanswered: log.note}, nil)
	e.cfg.SkipBaseline = false
	e.httpClient = newAbandonTestRequester(t)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}

	raw := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port))
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("127.0.0.1", port, false), raw)
	e.source = &sliceSource{items: []*work.WorkItem{work.NewWithModules(httpmsg.NewHttpRequestResponse(req, nil), nil)}}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(log.reasons) != 1 {
		t.Fatalf("OnUnanswered calls = %v, want 1", log.reasons)
	}
	for target, reason := range log.reasons {
		if reason != DropFetchError {
			t.Errorf("reason = %q, want %q", reason, DropFetchError)
		}
		if log.errs[target] == nil {
			t.Error("a fetch error carries its cause")
		}
	}

	// An item that answers is not unanswered.
	var answered unansweredLog
	e2, _ := newTestExecutor(ExecutorConfig{Workers: 1, OnUnanswered: answered.note}, nil)
	e2.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e2.scanCtx = &modules.ScanContext{}
	ok, _ := makeTestItem("example.com", "/", "<html>x</html>")
	e2.source = &sliceSource{items: []*work.WorkItem{ok}}
	if _, err := e2.Execute(context.Background()); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(answered.reasons) != 0 {
		t.Errorf("answered item reported unanswered: %v", answered.reasons)
	}
}
