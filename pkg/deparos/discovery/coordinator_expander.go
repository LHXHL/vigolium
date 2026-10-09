package discovery

import (
	"context"
	"errors"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"go.uber.org/zap"
)

// Expander scheduling.
//
// A single expander goroutine turns queued tasks into WorkItems. Expanding a
// 5k-word × extension wordlist takes as long as sending it, so running each
// Task.Expand to completion would leave a JS replay or spider task queued behind
// it for the whole sweep. Instead every expansion runs in its own producer
// goroutine feeding a small channel that the expander pulls from. Between items
// the expander can therefore park ("suspend") the current expansion and start a
// more urgent one, without any Task.Expand implementation knowing about it.
const (
	// preemptCheckInterval is how many items the expander pulls from the current
	// expansion between checks for a more urgent queued task.
	preemptCheckInterval = 64

	// maxSuspendedExpansions bounds the suspended stack. With the stack full the
	// current expansion runs on (inline tasks are still dispatched).
	maxSuspendedExpansions = 4

	// expansionBuffer is the per-expansion pull channel capacity: how far a
	// producer may run ahead of the expander, including while suspended.
	expansionBuffer = 16

	// inlineWorkerCount is the size of the dedicated inline worker pool that runs
	// JS replay, form submission and case-sense tasks.
	inlineWorkerCount = 2

	// inlineQueueSize bounds inline tasks handed off but not yet picked up. When
	// it is full the expander waits for an inline worker.
	inlineQueueSize = 64
)

// priorityBand groups task priorities into the urgency bands preemption works
// on: 0 = spider/JS fetch/form/JS replay (priorities 0-1), 1 = observed and
// short wordlists (2-7), 2 = long wordlists, malformed probes and fuzz (8+).
// A task preempts the current expansion only from a strictly lower band, so
// same-band tasks never thrash each other.
func priorityBand(p uint8) int {
	switch {
	case p <= 1:
		return 0
	case p <= 7:
		return 1
	default:
		return 2
	}
}

// isInlineTask reports whether a task executes inline (sends its own requests)
// rather than expanding into WorkItems.
func isInlineTask(task queue.TaskInfo) bool {
	switch task.(type) {
	case *CaseSenseDetectionTask, *JSExtractedRequestTask, *FormSubmissionTask:
		return true
	default:
		return false
	}
}

// expandedURL is one item produced by a Task.Expand call.
type expandedURL struct {
	url   string
	depth uint16
}

// expansion is one in-progress Task.Expand, running in a producer goroutine.
type expansion struct {
	task   Task
	band   int
	items  chan expandedURL // closed by the producer when Expand returns
	pulled int
}

// expander is the state of runExpander: the current expansion and the stack of
// suspended ones. Only the expander goroutine touches it.
type expander struct {
	c         *PayloadCoordinator
	ctx       context.Context // parent context: request sends and dequeues
	pctx      context.Context // producer context: cancelled when the expander exits
	cancel    context.CancelFunc
	producers sync.WaitGroup

	current   *expansion
	suspended []*expansion // stack; top is the most urgent suspended expansion
}

// runExpander pulls tasks from the queue, hands inline tasks to the inline
// workers and drives expansions into workChan, preempting a long expansion when
// a task from a more urgent band is queued. It returns when ctx is cancelled or
// the queue is stopped, and only after every producer goroutine has exited.
func (c *PayloadCoordinator) runExpander(ctx context.Context) {
	pctx, cancel := context.WithCancel(ctx)
	x := &expander{c: c, ctx: ctx, pctx: pctx, cancel: cancel}
	defer x.shutdown()

	for ctx.Err() == nil {
		if x.current == nil {
			if !x.next() {
				return
			}
			continue
		}
		x.step()
	}
}

// next picks the work to run when there is no current expansion: a queued task
// more urgent than every suspended expansion, else the most urgent suspended
// expansion, else (blocking) the next queued task. It returns false when the
// expander should exit.
func (x *expander) next() bool {
	c := x.c
	if n := len(x.suspended); n > 0 {
		top := x.suspended[n-1]
		// Nothing is displaced here, so the suspended-stack bound does not apply.
		if t := x.tryDequeueMoreUrgent(top.band, false); t != nil {
			x.dispatch(t)
			return true
		}
		if c.queue.IsStopped() {
			return false
		}
		x.suspended = x.suspended[:n-1]
		c.metrics.SuspendedExpansions.Add(-1)
		x.current = top
		logger.Debug("Resuming suspended task expansion",
			zap.String("description", top.task.Description()),
			zap.Int("items_sent", top.pulled))
		return true
	}

	taskInfo, err := c.queue.Dequeue(x.ctx)
	if err != nil {
		return !errors.Is(err, queue.ErrQueueStopped) && x.ctx.Err() == nil
	}
	if taskInfo != nil {
		x.dispatch(taskInfo)
	}
	return true
}

// step pulls one item from the current expansion and sends it to workChan.
// Every preemptCheckInterval items it checks the queue for a more urgent task.
func (x *expander) step() {
	cur := x.current
	select {
	case <-x.ctx.Done():
		return
	case it, ok := <-cur.items:
		if !ok {
			x.finish(cur)
			x.current = nil
			return
		}
		x.c.sendWorkItem(x.ctx, cur.task, it.url, it.depth)
		x.c.metrics.PayloadsProcessed.Add(1)
		cur.pulled++
		if cur.pulled%preemptCheckInterval == 0 {
			x.maybePreempt()
		}
	}
}

// maybePreempt dispatches queued inline tasks and, when a task from a strictly
// more urgent band heads the queue and the suspended stack has room, suspends
// the current expansion and starts that task instead.
func (x *expander) maybePreempt() {
	c := x.c
	for {
		p, ok := c.queue.PeekPriority()
		if !ok {
			return
		}
		// Fast path: the head can neither preempt nor be an inline task (all of
		// which are band 0).
		if band := priorityBand(p); band >= x.current.band && band != 0 {
			return
		}

		t := x.tryDequeueMoreUrgent(x.current.band, true)
		if t == nil {
			return
		}
		if isInlineTask(t) {
			x.dispatch(t)
			continue
		}
		task, ok := t.(Task)
		if !ok {
			logger.Error("Dequeued item is not a Task", zap.Any("taskInfo", t))
			continue
		}

		prev := x.current
		x.suspended = append(x.suspended, prev)
		c.metrics.SuspendedExpansions.Add(1)
		c.metrics.Preemptions.Add(1)
		logger.Debug("Suspending task expansion for a more urgent task",
			zap.String("suspended", prev.task.Description()),
			zap.Int("items_sent", prev.pulled),
			zap.String("preempting", task.Description()),
			zap.Uint8("priority", task.Priority()))
		x.current = nil
		x.start(task)
		return
	}
}

// tryDequeueMoreUrgent pops the queue head when it is an inline task, or when
// it belongs to a band strictly more urgent than band and (if displacing
// reports that the current expansion would be suspended) the suspended stack
// has room for it.
func (x *expander) tryDequeueMoreUrgent(band int, displacing bool) queue.TaskInfo {
	canSuspend := !displacing || len(x.suspended) < maxSuspendedExpansions
	return x.c.queue.TryDequeueIf(func(t queue.TaskInfo) bool {
		if isInlineTask(t) {
			return true
		}
		if _, ok := t.(Task); !ok {
			return true // let dispatch log and drop it
		}
		return canSuspend && priorityBand(t.Priority()) < band
	})
}

// dispatch routes a dequeued task: inline tasks go to the inline workers,
// everything else becomes the current expansion. The caller has already parked
// or finished any previous current expansion.
func (x *expander) dispatch(taskInfo queue.TaskInfo) {
	c := x.c
	task, ok := taskInfo.(Task)
	if !ok {
		logger.Error("Dequeued item is not a Task", zap.Any("taskInfo", taskInfo))
		return
	}

	if isInlineTask(task) {
		// Counted from hand-off, so IsIdle sees the task while it waits for a
		// free inline worker.
		c.metrics.InlineInFlight.Add(1)
		logger.Info("Dispatching inline task",
			zap.String("description", task.Description()),
			zap.String("baseURL", string(task.FullURL())),
			zap.Uint8("priority", task.Priority()))
		select {
		case c.inlineChan <- task:
		case <-x.ctx.Done():
			c.metrics.InlineInFlight.Add(-1)
		}
		return
	}

	x.start(task)
}

// start launches the producer goroutine for task and makes it the current
// expansion. The producer runs Task.Expand unchanged; its callback blocks on
// the pull channel, which is what lets the expander suspend it. Every send
// selects on the producer context so cancellation never strands the goroutine.
func (x *expander) start(task Task) {
	// Count the expansion before anything else, keeping the dequeue-to-count
	// window (where IsIdle could read a false idle) as short as possible.
	x.c.metrics.ExpansionsInFlight.Add(1)
	logger.Info("Starting task expansion",
		zap.String("description", task.Description()),
		zap.String("baseURL", string(task.FullURL())),
		zap.String("extension", task.Extension()),
		zap.Uint8("priority", task.Priority()))

	e := &expansion{
		task:  task,
		band:  priorityBand(task.Priority()),
		items: make(chan expandedURL, expansionBuffer),
	}
	x.producers.Add(1)
	pctx := x.pctx
	go func() {
		defer x.producers.Done()
		defer close(e.items)
		_ = task.Expand(pctx, func(u string, depth uint16) {
			select {
			case e.items <- expandedURL{url: u, depth: depth}:
			case <-pctx.Done():
			}
		})
	}()
	x.current = e
}

// finish records a fully drained expansion.
func (x *expander) finish(e *expansion) {
	x.c.metrics.ExpansionsInFlight.Add(-1)
	x.c.metrics.TasksCompleted.Add(1)

	// Don't log completion if context was cancelled during expansion
	if x.ctx.Err() != nil {
		return
	}
	logger.Info("Task expansion completed",
		zap.String("description", e.task.Description()),
		zap.String("baseURL", string(e.task.FullURL())))
}

// shutdown cancels every producer, releases the accounting of the expansions it
// abandons, and waits for all producer goroutines to exit.
func (x *expander) shutdown() {
	x.cancel()
	abandoned := len(x.suspended)
	x.c.metrics.SuspendedExpansions.Add(-int32(abandoned))
	if x.current != nil {
		abandoned++
	}
	x.c.metrics.ExpansionsInFlight.Add(-int32(abandoned))
	x.current = nil
	x.suspended = nil
	x.producers.Wait()
}

// runInlineWorker executes inline tasks handed off by the expander until
// inlineChan is closed. Once ctx is cancelled it drains without executing.
func (c *PayloadCoordinator) runInlineWorker(ctx context.Context) {
	for task := range c.inlineChan {
		if ctx.Err() == nil {
			c.executeInlineTask(ctx, task)
		}
		c.metrics.InlineInFlight.Add(-1)
	}
}
