package action

import (
	"sync"
	"testing"
)

// TestExtractorForTabSharesClickOnceMemory: a tab's extractor dedups against
// the elements every other tab already extracted for the same state, while
// keeping its own current-state namespace.
func TestExtractorForTabSharesClickOnceMemory(t *testing.T) {
	base := NewCandidateElementExtractorDefault()
	base.SetClickOnce(true)
	tab := base.ForTab()

	el := NewCandidateElement(NewIdentification(HowXPath, "/html/body/a[1]"), "", nil)

	base.SetCurrentState("s1")
	tab.SetCurrentState("s1")
	if !base.markChecked(el) {
		t.Fatal("first extraction of the element must be new")
	}
	if tab.markChecked(el) {
		t.Fatal("another tab re-extracted an element of the same state")
	}

	// The namespace is per extractor: the tab moving on does not move the base.
	tab.SetCurrentState("s2")
	if !tab.markChecked(el) {
		t.Fatal("same element in a different state must be new")
	}
	if base.markChecked(el) {
		t.Fatal("base extractor's namespace changed with the tab's")
	}
}

// TestExtractorForTabConcurrentClaims: concurrent tabs claiming the same keys
// each see every key exactly once in total.
func TestExtractorForTabConcurrentClaims(t *testing.T) {
	base := NewCandidateElementExtractorDefault()
	base.SetClickOnce(true)
	const tabs, elems = 4, 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < tabs; i++ {
		ex := base.ForTab()
		ex.SetCurrentState("s")
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < elems; n++ {
				el := NewCandidateElement(NewIdentification(HowXPath, "/a["+string(rune('0'+n%10))+"]["+string(rune('a'+n/10))+"]"), "", nil)
				if ex.markChecked(el) {
					mu.Lock()
					won++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if won != elems {
		t.Fatalf("new extractions across tabs = %d, want %d", won, elems)
	}
}
