package state

import (
	"fmt"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// TestPutIfAbsentConcurrentIdenticalDOM: tabs that capture the same DOM at the
// same moment get exactly one state, and all of them agree on it.
func TestPutIfAbsentConcurrentIdenticalDOM(t *testing.T) {
	g := NewGraph()
	const tabs = 32
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		added   int
		canonID = map[string]bool{}
	)
	start := make(chan struct{})
	for i := 0; i < tabs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := New(fmt.Sprintf("http://x/%d", i), "<p>same</p>", "<p>same</p>", 1)
			<-start
			canonical, ok := g.PutIfAbsent(s)
			mu.Lock()
			defer mu.Unlock()
			if ok {
				added++
			}
			canonID[canonical.ID] = true
		}(i)
	}
	close(start)
	wg.Wait()

	if added != 1 {
		t.Fatalf("states added = %d, want exactly 1", added)
	}
	if len(canonID) != 1 {
		t.Fatalf("tabs disagree on the canonical state: %v", canonID)
	}
	if g.StateCount() != 1 {
		t.Fatalf("graph has %d states, want 1", g.StateCount())
	}
}

// TestSwitchToStateConcurrentClone: several tabs (each with its own state
// machine) reach the same new DOM from the index at once. One of them creates
// the state; every other sees a clone, and each records its edge.
func TestSwitchToStateConcurrentClone(t *testing.T) {
	g := NewGraph()
	index := NewIndex("http://x/", "<index/>", "<index/>")
	g.AddState(index)

	const tabs = 16
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		fresh  int
		clones int
	)
	start := make(chan struct{})
	for i := 0; i < tabs; i++ {
		sm := NewStateMachine(g, index)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := New("http://x/next", "<next/>", "<next/>", 1)
			ev := action.NewEventable(action.NewIdentification(action.HowXPath, fmt.Sprintf("//a[%d]", i)), action.EventTypeClick)
			<-start
			_, isClone, _ := sm.SwitchToStateAndCheckIfClone(s, ev)
			mu.Lock()
			defer mu.Unlock()
			if isClone {
				clones++
			} else {
				fresh++
			}
			if cur := sm.GetCurrentState(); cur == nil || cur.ID != s.ID {
				t.Errorf("tab %d is not at the shared state", i)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if fresh != 1 || clones != tabs-1 {
		t.Fatalf("fresh=%d clones=%d, want 1 and %d", fresh, clones, tabs-1)
	}
	if g.StateCount() != 2 {
		t.Fatalf("graph has %d states, want 2", g.StateCount())
	}
	if got := len(g.OutgoingEdges(index.ID)); got != tabs {
		t.Fatalf("index has %d outgoing edges, want %d (one per distinct click)", got, tabs)
	}
}
