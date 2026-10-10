package core

import (
	"context"
	"sync"
	"sync/atomic"
)

// PauseController provides cooperative pause/resume for worker goroutines.
// Workers call WaitIfPaused between items; Pause blocks until no worker is
// mid-dispatch, then holds future workers until Resume is called.
//
// "Paused" covers the WORKERS only: Pause returns once every worker has finished
// its current item's fetch, passive stage and task dispatch. Active-module
// tasks the executor already dispatched run detached from their worker and are
// not waited for — they may still finish after Pause returns, and in doing so
// send probe traffic, emit findings, feed discovered URLs and acknowledge their
// item. No NEW item is dequeued or dispatched while paused.
//
// stateMu serializes the Pause/Resume transitions in full (including the mu
// Lock/Unlock that spans a pause), so concurrent Pause+Resume — reachable, e.g.
// a stop-triggered Runner.Close resuming while an API pause request is in flight
// — can never close a nil channel, unlock an unlocked mutex, or leave pausedCh
// stale relative to the paused flag.
type PauseController struct {
	mu       sync.RWMutex  // RLock held by active workers; write-locked for the pause duration
	stateMu  sync.Mutex    // serializes Pause/Resume transitions and guards pausedCh
	paused   atomic.Bool   // fast-path snapshot for WaitIfPaused/IsPaused
	pausedCh chan struct{} // non-nil and open while paused; closed on resume
}

// NewPauseController creates a new PauseController in the unpaused state.
func NewPauseController() *PauseController {
	return &PauseController{}
}

// Pause blocks new workers and waits for workers mid-dispatch to finish
// dispatching (not for the detached tasks they started; see PauseController).
// Safe to call multiple times (idempotent) and concurrently with Resume.
func (p *PauseController) Pause() {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.paused.Load() {
		return
	}
	// Create the resume channel BEFORE flipping the flag so a worker that observes
	// paused==true always reads a fresh, open channel (never nil or a stale closed
	// one). stateMu is held across mu.Lock() so a racing Resume can't unlock mu
	// before this Pause has locked it.
	p.pausedCh = make(chan struct{})
	p.paused.Store(true)
	// Acquire write lock — blocks until all RLocks (active workers) release.
	p.mu.Lock()
}

// Resume unblocks paused workers. Safe to call when not paused and concurrently
// with Pause.
func (p *PauseController) Resume() {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if !p.paused.CompareAndSwap(true, false) {
		return
	}
	close(p.pausedCh)
	p.mu.Unlock()
}

// IsPaused returns the current pause state.
func (p *PauseController) IsPaused() bool {
	return p.paused.Load()
}

// WaitIfPaused blocks the caller if the controller is paused.
// Returns false if the context is cancelled while waiting.
// Workers should call this between processing items.
func (p *PauseController) WaitIfPaused(ctx context.Context) bool {
	if !p.paused.Load() {
		return true
	}
	// Read a consistent (paused, channel) snapshot under stateMu so we never
	// select on a nil or stale channel raced in by a concurrent Pause/Resume.
	p.stateMu.Lock()
	paused := p.paused.Load()
	ch := p.pausedCh
	p.stateMu.Unlock()
	if !paused || ch == nil {
		return true
	}
	// Wait for resume or context cancellation
	select {
	case <-ctx.Done():
		return false
	case <-ch:
		return true
	}
}

// AcquireWorker acquires a read lock for the duration of a worker's part of an
// item (fetch, passive stage, task dispatch).
// Call ReleaseWorker when done. Returns false if paused (caller should
// call WaitIfPaused first).
func (p *PauseController) AcquireWorker() {
	p.mu.RLock()
}

// ReleaseWorker releases the read lock after item processing.
func (p *PauseController) ReleaseWorker() {
	p.mu.RUnlock()
}
