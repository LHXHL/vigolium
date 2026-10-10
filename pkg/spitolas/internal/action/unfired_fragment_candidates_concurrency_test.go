package action

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func oneAction(stateID string) []*CandidateElement {
	return []*CandidateElement{
		NewCandidateElement(NewIdentification(HowXPath, "//a[@id='"+stateID+"']"), "", nil),
	}
}

// TestAwaitStateMultiConsumerTermination runs N consumers over a frontier that
// grows while it is crawled: each state, when processed, adds up to fanout
// child states. The consumers may only stop once the queue is empty AND none
// of them is active, so every state ever added is processed exactly once, no
// two consumers hold the same state at once, and every consumer returns.
func TestAwaitStateMultiConsumerTermination(t *testing.T) {
	defer goleak.VerifyNone(t)

	const (
		consumers = 6
		fanout    = 3
		maxStates = 200
	)
	u := NewUnfiredFragmentCandidates(nil, nil)

	var (
		mu        sync.Mutex
		created   = map[string]bool{"s0": true}
		processed = map[string]int{}
		inFlight  = map[string]bool{}
		next      atomic.Int64
	)
	u.AddActions(oneAction("s0"), "s0")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, consumers)
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				id, err := u.AwaitState(ctx, "normal")
				if err != nil {
					errs <- err
					return
				}
				if id == "" {
					return // drained
				}
				mu.Lock()
				if inFlight[id] {
					mu.Unlock()
					errs <- fmt.Errorf("state %s handed to two consumers at once", id)
					u.TaskDone(id)
					return
				}
				inFlight[id] = true
				processed[id]++
				mu.Unlock()

				// Fire the state's action (atomic pop), then discover children.
				if act := u.PollByMode(id, "normal", true); act == nil {
					errs <- fmt.Errorf("state %s claimed with no action", id)
				}
				time.Sleep(time.Millisecond) // let the others interleave
				for c := 0; c < fanout; c++ {
					n := next.Add(1)
					if n >= maxStates {
						break
					}
					child := fmt.Sprintf("s%d", n)
					mu.Lock()
					created[child] = true
					mu.Unlock()
					u.AddActions(oneAction(child), child)
				}

				mu.Lock()
				delete(inFlight, id)
				mu.Unlock()
				u.TaskDone(id)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if len(processed) != len(created) {
		t.Fatalf("processed %d states, created %d", len(processed), len(created))
	}
	for id := range created {
		if processed[id] != 1 {
			t.Errorf("state %s processed %d times, want 1", id, processed[id])
		}
	}
	if got := u.ActiveConsumers(); got != 0 {
		t.Errorf("active consumers after drain = %d, want 0", got)
	}
	if u.HasPending() {
		t.Error("actions still pending after drain")
	}
}

// TestAwaitStateNoLostWakeup: a consumer waiting while another holds the only
// state must wake for a state the holder adds, and must not see the frontier
// as drained while the holder is active.
func TestAwaitStateNoLostWakeup(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := NewUnfiredFragmentCandidates(nil, nil)
	u.AddActions(oneAction("a"), "a")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first, err := u.AwaitState(ctx, "normal")
	if err != nil || first != "a" {
		t.Fatalf("first claim = %q, %v", first, err)
	}
	_ = u.PollByMode("a", "normal", true)

	got := make(chan string, 1)
	go func() {
		id, err := u.AwaitState(ctx, "normal")
		if err != nil {
			id = "error: " + err.Error()
		}
		got <- id
	}()

	select {
	case id := <-got:
		t.Fatalf("second consumer returned %q while the first was still active", id)
	case <-time.After(100 * time.Millisecond):
	}

	u.AddActions(oneAction("b"), "b")
	select {
	case id := <-got:
		if id != "b" {
			t.Fatalf("second consumer got %q, want b", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second consumer was not woken by the new state")
	}
	_ = u.PollByMode("b", "normal", true)
	u.TaskDone("b")
	u.TaskDone("a")

	// Both released and nothing pending: drained.
	if id, err := u.AwaitState(ctx, "normal"); id != "" || err != nil {
		t.Fatalf("after drain AwaitState = %q, %v; want drained", id, err)
	}
}

// TestAwaitStateWakesOnLastTaskDone: waiters blocked on an active consumer all
// return drained when it finishes without adding work.
func TestAwaitStateWakesOnLastTaskDone(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := NewUnfiredFragmentCandidates(nil, nil)
	u.AddActions(oneAction("a"), "a")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if id, _ := u.AwaitState(ctx, "normal"); id != "a" {
		t.Fatalf("claim = %q", id)
	}
	_ = u.PollByMode("a", "normal", true)

	const waiters = 4
	done := make(chan string, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			id, _ := u.AwaitState(ctx, "normal")
			done <- id
		}()
	}
	time.Sleep(50 * time.Millisecond)
	u.TaskDone("a")
	for i := 0; i < waiters; i++ {
		select {
		case id := <-done:
			if id != "" {
				t.Errorf("waiter got %q, want drained", id)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("waiter not woken by the last TaskDone")
		}
	}
}

// TestAwaitStateContextCancelWakesWaiters: cancelling the context releases a
// waiter that would otherwise wait on an active consumer forever.
func TestAwaitStateContextCancelWakesWaiters(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := NewUnfiredFragmentCandidates(nil, nil)
	u.AddActions(oneAction("a"), "a")
	if id := u.PollStateByPriority("normal"); id != "a" {
		t.Fatalf("claim = %q", id)
	}
	_ = u.PollByMode("a", "normal", true)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := u.AwaitState(ctx, "normal")
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("want a context error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter not woken by context cancellation")
	}
	u.TaskDone("a")
}

// TestPollStateByPrioritySkipsClaimed: a claimed state is not handed out again
// until TaskDone, and is re-offered then if it still has actions.
func TestPollStateByPrioritySkipsClaimed(t *testing.T) {
	u := NewUnfiredFragmentCandidates(nil, nil)
	u.AddActions(append(oneAction("a"), oneAction("a2")...), "a")
	u.AddActions(oneAction("b"), "b")

	if got := u.PollStateByPriority("normal"); got != "a" {
		t.Fatalf("first = %q, want a", got)
	}
	if got := u.PollStateByPriority("normal"); got != "b" {
		t.Fatalf("second = %q, want b (a is claimed)", got)
	}
	if got := u.PollStateByPriority("normal"); got != "" {
		t.Fatalf("third = %q, want none", got)
	}
	_ = u.PollByMode("a", "normal", true)
	u.TaskDone("a")
	if got := u.PollStateByPriority("normal"); got != "a" {
		t.Fatalf("after release = %q, want a (one action left)", got)
	}
}

// TestCandidatesStatsUnderWriters: Stats must not deadlock against writers
// (it used to take the read lock twice).
func TestCandidatesStatsUnderWriters(t *testing.T) {
	u := NewUnfiredFragmentCandidates(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for n := 0; ctx.Err() == nil && n < 2000; n++ {
				id := fmt.Sprintf("w%d-%d", i, n)
				u.AddActions(oneAction(id), id)
			}
		}(i)
		go func() {
			defer wg.Done()
			for n := 0; ctx.Err() == nil && n < 2000; n++ {
				_ = u.Stats()
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		t.Fatal("Stats/AddActions did not finish (deadlock?)")
	}
}
