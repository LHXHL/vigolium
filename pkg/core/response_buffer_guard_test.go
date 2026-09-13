package core

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// slowPassiveModule blocks past its timeout hint so its wrapper abandons the
// call while the module goroutine is still running and still holding the item.
type slowPassiveModule struct {
	id      string
	block   chan struct{}
	started chan struct{}
	// bodySeen is the response body the module read AFTER it was abandoned.
	bodySeen chan string
}

func (m *slowPassiveModule) ID() string                                     { return m.id }
func (m *slowPassiveModule) Name() string                                   { return m.id }
func (m *slowPassiveModule) Description() string                            { return "" }
func (m *slowPassiveModule) ShortDescription() string                       { return "" }
func (m *slowPassiveModule) ConfirmationCriteria() string                   { return "" }
func (m *slowPassiveModule) Severity() severity.Severity                    { return 0 }
func (m *slowPassiveModule) Confidence() severity.Confidence                { return 0 }
func (m *slowPassiveModule) ScanScopes() modules.ScanScope                  { return modkit.ScanScopeRequest }
func (m *slowPassiveModule) Tags() []string                                 { return nil }
func (m *slowPassiveModule) CanProcess(_ *httpmsg.HttpRequestResponse) bool { return true }
func (m *slowPassiveModule) Scope() modules.PassiveScanScope {
	return modkit.PassiveScanScopeBoth
}

// TimeoutHint puts this module on the enforced-timeout path (the goroutine +
// select), which is where abandonment happens.
func (m *slowPassiveModule) TimeoutHint() time.Duration { return 20 * time.Millisecond }

func (m *slowPassiveModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	close(m.started)
	<-m.block // outlive the wrapper's timeout
	// Read the body only now — after processItem has returned and would have
	// recycled the buffer.
	if item != nil && item.Response() != nil {
		m.bodySeen <- string(item.Response().Body())
	} else {
		m.bodySeen <- ""
	}
	return nil, nil
}

func (m *slowPassiveModule) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// TestAbandonedModuleKeepsResponseBufferOutOfPool is the regression test for a
// timed-out module reading another request's response.
//
// processItem builds the baseline over a pooled buffer and returns it to the
// pool on exit. A module that blew its timeout keeps running with the same item,
// so recycling that buffer lets the next item overwrite the bytes the abandoned
// module is still scanning — and any finding it reports is then attributed to the
// wrong request. The guard withholds the buffer instead.
func TestAbandonedModuleKeepsResponseBufferOutOfPool(t *testing.T) {
	mod := &slowPassiveModule{
		id:       "slow-passive",
		block:    make(chan struct{}),
		started:  make(chan struct{}),
		bodySeen: make(chan string, 1),
	}

	e, _ := newTestExecutor(ExecutorConfig{}, []modules.PassiveModule{mod})

	// Body lives in a buffer taken from the executor's own pool, exactly as
	// fetchBaseline would allocate it.
	const marker = "ORIGINAL-BODY-MARKER"
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
	raw := head + marker
	buf := getResponseBuffer(len(raw))
	copy(buf, raw)

	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte("GET /slow HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	)
	rr := httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse(buf))

	// Drive the wrapper directly with the guard attached, mirroring what
	// processItem does around a pooled buffer.
	var guard responseBufferGuard
	ctx := withResponseBufferGuard(context.Background(), &guard)

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runPassiveWithTimeout(
			ctx,
			func(_ context.Context) ([]*output.ResultEvent, error) {
				return mod.ScanPerRequest(rr, nil)
			},
			mod, rr,
		)
	}()

	<-mod.started
	<-done // the wrapper gave up; the module goroutine is still running

	if !guard.escaped.Load() {
		t.Fatal("abandoned module did not mark the response buffer as escaped")
	}

	// processItem's deferred release is a no-op for this item: the guard is set,
	// so buf is NOT handed back to the pool. Simulate the next item taking a
	// buffer — since buf never went back, it cannot be the same memory.
	next := getResponseBuffer(len(raw))
	for i := range next {
		next[i] = 'X'
	}

	// Let the abandoned module finish reading.
	close(mod.block)
	select {
	case got := <-mod.bodySeen:
		if got != marker {
			t.Errorf("abandoned module read %q, want %q — its response buffer was recycled underneath it", got, marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the abandoned module")
	}
}

// TestMarkResponseBufferEscapedWithoutGuard covers the no-guard path: wrappers
// called outside processItem must not panic.
func TestMarkResponseBufferEscapedWithoutGuard(t *testing.T) {
	markResponseBufferEscaped(context.Background())
}
