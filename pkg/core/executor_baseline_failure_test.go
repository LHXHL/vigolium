package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// TestBaselineFailureRefused: a target whose port is closed never answers, so
// Responded stays 0 and the failure is kept with class "refused" — the
// explanation the never-silent reporting needs.
func TestBaselineFailureRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
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
	if got := e.Responded(); got != 0 {
		t.Fatalf("Responded() = %d, want 0", got)
	}
	if rep := e.Report(); rep.Responded != 0 {
		t.Errorf("Report().Responded = %d, want 0", rep.Responded)
	}
	failures := e.BaselineFailures()
	if len(failures) != 1 {
		t.Fatalf("BaselineFailures() = %+v, want 1 entry", failures)
	}
	f := failures[0]
	if f.Class != http.TransportErrRefused {
		t.Errorf("Class = %q (detail %q), want %q", f.Class, f.Detail, http.TransportErrRefused)
	}
	if !strings.Contains(f.Target, fmt.Sprintf("127.0.0.1:%d", port)) || f.Detail == "" {
		t.Errorf("failure = %+v, want target with port %d and a detail", f, port)
	}
}

func TestBaselineFailureRingBounded(t *testing.T) {
	t.Parallel()
	e := &Executor{}
	if got := e.BaselineFailures(); got != nil {
		t.Fatalf("empty ring = %+v, want nil", got)
	}
	const n = baselineFailureCap + 5
	for i := 0; i < n; i++ {
		e.recordBaselineFailure(fmt.Sprintf("http://h%d/", i), errors.New(strings.Repeat("x", 1000)))
	}
	got := e.BaselineFailures()
	if len(got) != baselineFailureCap {
		t.Fatalf("len = %d, want %d", len(got), baselineFailureCap)
	}
	// Oldest retained first, newest last.
	if got[0].Target != "http://h5/" || got[len(got)-1].Target != fmt.Sprintf("http://h%d/", n-1) {
		t.Errorf("order: first %q last %q", got[0].Target, got[len(got)-1].Target)
	}
	if len(got[0].Detail) > baselineFailureDetailMax || got[0].Class != http.TransportErrOther {
		t.Errorf("entry = %+v", got[0])
	}
}
