package core

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// countedSliceSource is a sliceSource that reports its size only once it has
// been read from, like a database source that counts on its first Next.
type countedSliceSource struct {
	sliceSource
	read bool
}

func (s *countedSliceSource) Next(ctx context.Context) (*work.WorkItem, error) {
	s.read = true
	return s.sliceSource.Next(ctx)
}

func (s *countedSliceSource) Count() int64 {
	if !s.read {
		return 0
	}
	return int64(len(s.items))
}

// TestExecutorObserverSeesEveryRun pins the seam the runner's phase progress
// reads through: an Execute under an observer context reports its executor, and
// KnownTotal reads the source live rather than the value at construction.
func TestExecutorObserverSeesEveryRun(t *testing.T) {
	t.Parallel()
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}
	e.statsTracker = stats.New(0, false)
	a, _ := makeTestItem("example.com", "/a", "<html>a</html>")
	b, _ := makeTestItem("example.com", "/b", "<html>b</html>")
	src := &countedSliceSource{sliceSource: sliceSource{items: []*work.WorkItem{a, b}}}
	e.source = src

	if got := e.KnownTotal(); got != 0 {
		t.Fatalf("KnownTotal before the run = %d, want 0 (source not read yet)", got)
	}

	var seen []*Executor
	ctx := WithExecutorObserver(context.Background(), func(x *Executor) { seen = append(seen, x) })
	if _, err := e.Execute(ctx); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seen) != 1 || seen[0] != e {
		t.Fatalf("observer saw %v, want exactly the executor that ran", seen)
	}
	if got := e.KnownTotal(); got != 2 {
		t.Errorf("KnownTotal after the run = %d, want 2", got)
	}
	if got := e.Processed(); got != 2 {
		t.Errorf("Processed = %d, want 2", got)
	}
}

// TestExecutorObserverAbsentIsNoop: a plain context, and a nil observer, change
// nothing.
func TestExecutorObserverAbsentIsNoop(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if WithExecutorObserver(ctx, nil) != ctx {
		t.Error("a nil observer must return the context unchanged")
	}
	notifyExecutorObserver(ctx, nil) // must not panic
	var nilExec *Executor
	if nilExec.KnownTotal() != 0 {
		t.Error("KnownTotal on a nil executor must be 0")
	}
}
