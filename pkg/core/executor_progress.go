package core

import "context"

// executorObserverKey carries an ExecutorObserver on a context.
type executorObserverKey struct{}

// ExecutorObserver is told about every Executor that starts running under a
// context that carries it.
//
// It exists so a caller that owns a whole stretch of work (the runner's phase
// tracker) can read progress off every executor that stretch builds, without
// each of the places that build one having to hand it over. A dynamic-assessment
// phase builds one executor per feedback round, deep inside its own loop; the
// phase's progress is the sum over all of them.
type ExecutorObserver func(*Executor)

// WithExecutorObserver returns a context whose Execute calls report their
// executor to fn. A nil fn returns ctx unchanged.
func WithExecutorObserver(ctx context.Context, fn ExecutorObserver) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, executorObserverKey{}, fn)
}

// notifyExecutorObserver hands e to the observer carried on ctx, if any.
func notifyExecutorObserver(ctx context.Context, e *Executor) {
	if ctx == nil {
		return
	}
	if fn, ok := ctx.Value(executorObserverKey{}).(ExecutorObserver); ok && fn != nil {
		fn(e)
	}
}

// KnownTotal returns the number of items the executor's input source says it
// holds, or 0 when the source cannot say (it does not implement
// source.Countable).
//
// Read live, not captured at construction: a database-backed source learns its
// count on its first Next, so a reading taken before the run starts is 0 and a
// later one is the real bound.
func (e *Executor) KnownTotal() int64 {
	if e == nil {
		return 0
	}
	return getKnownTotal(e.source)
}
