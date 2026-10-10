package core

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

// Tests for dispatch-and-detach: a worker dispatches an item's active tasks and
// goes back to the queue; the item completes (ack, Processed, buffer return)
// when its last task returns.

// hookedRequestModule is a per-request active module whose scan runs hook. It
// implements ContextualActiveModule so a hook can observe phase cancellation.
type hookedRequestModule struct {
	activeStub
	hook func(ctx context.Context, item *httpmsg.HttpRequestResponse, sc *modules.ScanContext)
}

func newHookedModule(hook func(context.Context, *httpmsg.HttpRequestResponse, *modules.ScanContext)) *hookedRequestModule {
	return &hookedRequestModule{
		activeStub: activeStub{id: "hooked", scopes: modules.ScanScopeRequest, canProc: true},
		hook:       hook,
	}
}

func (m *hookedRequestModule) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *protohttp.Requester, sc *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.hook(context.Background(), item, sc)
	return nil, nil
}

func (m *hookedRequestModule) ScanPerInsertionPointContext(context.Context, *httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func (m *hookedRequestModule) ScanPerRequestContext(ctx context.Context, item *httpmsg.HttpRequestResponse, _ *protohttp.Requester, sc *modules.ScanContext) ([]*output.ResultEvent, error) {
	m.hook(ctx, item, sc)
	return nil, nil
}

func (m *hookedRequestModule) ScanPerHostContext(context.Context, *httpmsg.HttpRequestResponse, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func pathOf(item *httpmsg.HttpRequestResponse) string { return item.Request().Path() }

// ackedItem builds a work item (response attached, so SkipBaseline needs no
// network) whose ack increments acks.
func ackedItem(path string, acks *atomic.Int64) *work.WorkItem {
	_, rr := makeTestItem("hol.example.test", path, "<html>ok</html>")
	return work.NewWithCallback(rr, nil, func() { acks.Add(1) })
}

func plainItems(paths ...string) []*work.WorkItem {
	out := make([]*work.WorkItem, len(paths))
	for i, p := range paths {
		out[i], _ = makeTestItem("hol.example.test", p, "<html>ok</html>")
	}
	return out
}

// runExecute starts Execute in the background and returns a channel closed
// when it returns.
func runExecute(t *testing.T, e *Executor, ctx context.Context) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := e.Execute(ctx); err != nil {
			t.Errorf("Execute: %v", err)
		}
	}()
	return done
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestNoHeadOfLineBlocking(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	releaseA := make(chan struct{})
	enteredA := make(chan struct{})
	bRan := make(chan struct{})
	mod := newHookedModule(func(_ context.Context, item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) {
		switch pathOf(item) {
		case "/a":
			close(enteredA)
			<-releaseA
		case "/b":
			close(bRan)
		}
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true},
		&sliceSource{items: plainItems("/a", "/b")}, []modules.ActiveModule{mod}, nil)

	done := runExecute(t, e, context.Background())
	waitClosed(t, enteredA, "item A's task to start")
	// The single worker must not be pinned by A's task: B's task runs while A's
	// is still blocked.
	waitClosed(t, bRan, "item B's task while A's task is still running")
	close(releaseA)
	waitClosed(t, done, "Execute to return")

	if got := e.Processed(); got != 2 {
		t.Fatalf("Processed() = %d, want 2", got)
	}
}

func TestAckAfterAllTasks(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var acks atomic.Int64
	release := make(chan struct{})
	entered := make(chan struct{})
	mod := newHookedModule(func(context.Context, *httpmsg.HttpRequestResponse, *modules.ScanContext) {
		close(entered)
		<-release
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true},
		&sliceSource{items: []*work.WorkItem{ackedItem("/slow", &acks)}}, []modules.ActiveModule{mod}, nil)

	done := runExecute(t, e, context.Background())
	waitClosed(t, entered, "the slow task to start")
	// The worker is back in its loop, but the item is still open.
	time.Sleep(50 * time.Millisecond)
	if got := acks.Load(); got != 0 {
		t.Fatalf("item acknowledged %d time(s) while its task was still running", got)
	}
	if got := e.Processed(); got != 0 {
		t.Fatalf("Processed() = %d while the task was still running, want 0", got)
	}
	if got := e.InFlight(); got != 1 {
		t.Fatalf("InFlight() = %d while the task was still running, want 1 (outstanding items)", got)
	}

	close(release)
	waitClosed(t, done, "Execute to return")
	if got := acks.Load(); got != 1 {
		t.Fatalf("acks = %d after the task finished, want 1", got)
	}
	if got := e.Processed(); got != 1 {
		t.Fatalf("Processed() = %d, want 1", got)
	}
	if got := e.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d after completion, want 0", got)
	}
}

func TestOutstandingItemsBound(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	paths := []string{"/i0", "/i1", "/i2"}
	release := map[string]chan struct{}{}
	for _, p := range paths {
		release[p] = make(chan struct{})
	}
	var mu sync.Mutex
	var entered []string
	enteredCh := make(chan string, len(paths))
	mod := newHookedModule(func(_ context.Context, item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) {
		p := pathOf(item)
		mu.Lock()
		entered = append(entered, p)
		mu.Unlock()
		enteredCh <- p
		<-release[p]
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true, MaxOutstandingItems: 2},
		&sliceSource{items: plainItems(paths...)}, []modules.ActiveModule{mod}, nil)

	done := runExecute(t, e, context.Background())
	first := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case p := <-enteredCh:
			first[p] = true
		case <-time.After(5 * time.Second):
			t.Fatal("first two items never started")
		}
	}
	// Both slots are held by blocked tasks: the third item must not be dequeued.
	select {
	case p := <-enteredCh:
		t.Fatalf("item %s started with MaxOutstandingItems=2 already outstanding", p)
	case <-time.After(150 * time.Millisecond):
	}
	if got := e.InFlight(); got != 2 {
		t.Fatalf("InFlight() = %d, want 2", got)
	}

	// Finish one: its slot frees and the third item proceeds.
	var freed string
	for p := range first {
		freed = p
		break
	}
	close(release[freed])
	var third string
	select {
	case third = <-enteredCh:
	case <-time.After(5 * time.Second):
		t.Fatal("third item never started after a slot was freed")
	}
	if first[third] {
		t.Fatalf("item %s started twice", third)
	}
	for _, p := range paths {
		if p != freed {
			close(release[p])
		}
	}
	waitClosed(t, done, "Execute to return")
	if got := e.Processed(); got != 3 {
		t.Fatalf("Processed() = %d, want 3", got)
	}
}

func TestFeedbackFromDetachedTaskIsDrained(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	otherRan := make(chan struct{})
	var fedSeen atomic.Bool
	mod := newHookedModule(func(_ context.Context, item *httpmsg.HttpRequestResponse, sc *modules.ScanContext) {
		switch pathOf(item) {
		case "/seed":
			// By the time /other's task runs, the single worker has left /seed
			// behind and gone back to the queue.
			<-otherRan
			time.Sleep(20 * time.Millisecond)
			_, fed := makeTestItem("hol.example.test", "/fed", "<html>fed</html>")
			if !sc.RequestFeeder.Feed(fed) {
				t.Error("feedback channel refused the discovered request")
			}
		case "/other":
			close(otherRan)
		case "/fed":
			fedSeen.Store(true)
		}
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true},
		&sliceSource{items: plainItems("/seed", "/other")}, []modules.ActiveModule{mod}, nil)

	done := runExecute(t, e, context.Background())
	waitClosed(t, done, "Execute to return")
	if !fedSeen.Load() {
		t.Fatal("an item fed back by a detached task was not processed before Execute returned")
	}
	if got := e.Processed(); got != 3 {
		t.Fatalf("Processed() = %d, want 3 (two inputs + one fed)", got)
	}
}

func TestPanicInDetachedTaskForcesAck(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	e := NewExecutor(ExecutorConfig{Workers: 1}, nil, nil, nil)
	e.pool.activeTaskSem = make(chan struct{}, 1)

	var acks atomic.Int64
	item := ackedItem("/poison", &acks)
	// The item's context is already cancelled, which on its own would withhold
	// the ack. The panic must force it (poison-item rule).
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tr := e.newItemTracker(cancelled, item, false)
	// The task panics before handing its slot to a module wrapper.
	e.goActiveTask(context.Background(), tr, func(func()) { panic("boom") })
	tr.done()
	waitClosed(t, tr.finished, "the item to complete")

	if got := acks.Load(); got != 1 {
		t.Fatalf("acks = %d, want 1: a panicked item must be acknowledged", got)
	}
	if got := e.Report().Unacked; got != 0 {
		t.Fatalf("Unacked = %d, want 0", got)
	}
	if got := len(e.pool.activeTaskSem); got != 0 {
		t.Fatalf("active-task slot leaked by the panicking task (%d held)", got)
	}
	if got := e.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d, want 0", got)
	}
}

func TestCancelWithDetachedTasks(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	const n = 6
	var acks atomic.Int64
	var started atomic.Int64
	allStarted := make(chan struct{})
	mod := newHookedModule(func(ctx context.Context, item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) {
		if strings.HasPrefix(pathOf(item), "/never") {
			t.Error("an item queued behind the cancellation was processed")
		}
		if started.Add(1) == 4 {
			close(allStarted)
		}
		<-ctx.Done() // a module that honours cancellation
	})
	items := make([]*work.WorkItem, 0, n)
	for i := 0; i < 4; i++ {
		items = append(items, ackedItem("/held", &acks))
	}
	for i := 0; i < n-4; i++ {
		items = append(items, ackedItem("/never", &acks))
	}
	e := NewExecutor(ExecutorConfig{Workers: 2, SkipBaseline: true, MaxOutstandingItems: 4,
		WorkerExitGrace: 3 * time.Second},
		&sliceSource{items: items}, []modules.ActiveModule{mod}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := runExecute(t, e, ctx)
	waitClosed(t, allStarted, "four tasks to start")
	start := time.Now()
	cancel()
	waitClosed(t, done, "Execute to return after cancel")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Execute took %s to return after cancel", elapsed)
	}

	if got := acks.Load(); got != 0 {
		t.Fatalf("acks = %d, want 0: items interrupted by cancellation must not be acknowledged", got)
	}
	rep := e.Report()
	if rep.Unacked != 4 {
		t.Fatalf("Unacked = %d, want 4 (the interrupted items)", rep.Unacked)
	}
	if rep.WorkersAbandoned {
		t.Fatal("WorkersAbandoned set although every task honoured cancellation")
	}
	if got := e.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d after Execute returned, want 0", got)
	}
}

func TestBufferNotReturnedWhileTaskRunning(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	e := NewExecutor(ExecutorConfig{Workers: 1}, nil, nil, nil)
	item, _ := makeTestItem("hol.example.test", "/buf", "ok")

	var returned [][]byte
	var mu sync.Mutex
	newTracker := func() *itemTracker {
		tr := e.newItemTracker(context.Background(), item, false)
		tr.pooledBuf = make([]byte, 16)
		tr.releaseBuf = func(b []byte) {
			mu.Lock()
			returned = append(returned, b)
			mu.Unlock()
		}
		return tr
	}
	returnedCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(returned)
	}

	tr := newTracker()
	buf := tr.pooledBuf
	release1, release2 := make(chan struct{}), make(chan struct{})
	for _, rel := range []chan struct{}{release1, release2} {
		e.goActiveTask(context.Background(), tr, func(releaseSlot func()) {
			defer releaseSlot()
			<-rel
		})
	}
	tr.done() // dispatcher done; two tasks still hold the item
	close(release1)
	time.Sleep(30 * time.Millisecond)
	if got := returnedCount(); got != 0 {
		t.Fatalf("buffer returned to the pool while a task was still running")
	}
	close(release2)
	waitClosed(t, tr.finished, "the item to complete")
	if got := returnedCount(); got != 1 {
		t.Fatalf("buffer returned %d time(s), want 1", got)
	}
	if &returned[0][0] != &buf[0] {
		t.Fatal("a different buffer was returned")
	}

	// An abandoned module call may still read the buffer: never pool it.
	tr = newTracker()
	markResponseBufferEscaped(tr.ctx)
	tr.done()
	waitClosed(t, tr.finished, "the escaped item to complete")
	if got := returnedCount(); got != 1 {
		t.Fatalf("an escaped buffer was returned to the pool")
	}
}
