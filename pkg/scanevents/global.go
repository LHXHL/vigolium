package scanevents

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// The stream has exactly one writer per process — stdout — and its producers are
// spread across packages that do not otherwise know about each other (the
// runner's phase loop, the shared requester's block notifier, the host limiter's
// pre-arm sink, the bridge importer). Threading an emitter through every one of
// them would mean a parameter on a dozen constructors whose only purpose is to
// be nil in the common case, so the stream is addressed the way zap's logger is:
// a package-level default, installed once at startup, no-op until then.
//
// A -P/--parallel fan-out runs each target as its own child PROCESS, so
// "one process, one stream" holds there too — the children's streams are
// separate pipes, and each event's scan_uuid says which invocation it came from.
var (
	globalMu sync.RWMutex
	global   *Emitter
)

// Install makes e the process default. Passing nil disables the stream.
func Install(e *Emitter) {
	globalMu.Lock()
	global = e
	globalMu.Unlock()
}

// Default returns the process emitter. The result may be nil, which every
// Emitter method tolerates — callers do not need a nil check.
func Default() *Emitter {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// On reports whether a stream is attached. Use it to skip work that exists only
// to build an event (counting rows, formatting a detail string), never to guard
// an Emit call.
func On() bool { return Default().Enabled() }

// Emit writes one event to the process default.
func Emit(ev Event) { Default().Emit(ev) }

// Finish emits the terminal scan.finished event on the process default, once per
// emitter. Installing a fresh emitter (the next scan in a multi-target run)
// arms a fresh latch — see Emitter.terminalOnce.
func Finish(ev Event) { Default().Finish(ev) }

// TrapSignals arranges for a terminal scan.finished{status:"interrupted"} on
// SIGINT/SIGTERM, then lets the process take its normal course.
//
// The event is emitted BEFORE any graceful shutdown the caller has registered,
// not after: a graceful Close can take seconds, and an operator who sent a
// second Ctrl+C in that window gets a hard exit. Writing first means the
// consumer learns the run was interrupted even on the impatient path — the one
// where it most needs to know.
//
// Returns a stop function that unregisters the handler.
func TrapSignals(start time.Time) func() {
	if !On() {
		return func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			Finish(Event{
				Status:     StatusInterrupted,
				DurationMS: time.Since(start).Milliseconds(),
			})
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
