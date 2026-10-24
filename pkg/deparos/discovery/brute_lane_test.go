package discovery

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
)

// Wordlist and FUZZ-template items go to the brute-force lane; everything
// else (observed words, extension variants, spider work) stays on the shared
// workers, so only wordlist fuzzing runs wider.
func TestBruteForceItemsUseTheirOwnLane(t *testing.T) {
	c := NewPayloadCoordinator(queue.New(), 2, &Callbacks{})
	c.SetBruteForceWorkers(8)
	if c.bruteWorkers != 8 || cap(c.bruteChan) != 16 {
		t.Fatalf("brute lane = %d workers, chan cap %d; want 8 and 16", c.bruteWorkers, cap(c.bruteChan))
	}

	ctx := context.Background()
	wordlist := testWordlistTask()
	fuzzTask := NewFuzzTask(&FuzzTaskConfig{URLTemplate: "http://a.test/FUZZ", Provider: payload.NewLazyCustomProviderFromInline("t", []string{"x"})})
	other := &stubExpandTask{name: "observed", priority: 3}

	c.sendWorkItem(ctx, wordlist, "http://a.test/admin", 0)
	c.sendWorkItem(ctx, fuzzTask, "http://a.test/x", 0)
	c.sendWorkItem(ctx, other, "http://a.test/seen", 0)

	if got := len(c.bruteChan); got != 2 {
		t.Errorf("brute lane holds %d items, want the wordlist and FUZZ items", got)
	}
	if got := len(c.workChan); got != 1 {
		t.Errorf("shared lane holds %d items, want only the observed item", got)
	}
	if c.IsIdle() {
		t.Error("IsIdle with items queued on the brute lane")
	}
}

// Without a brute lane every item shares the workers, as before.
func TestNoBruteLaneKeepsOneQueue(t *testing.T) {
	c := NewPayloadCoordinator(queue.New(), 2, &Callbacks{})
	c.SetBruteForceWorkers(0)
	wordlist := testWordlistTask()
	c.sendWorkItem(context.Background(), wordlist, "http://a.test/admin", 0)
	if c.bruteChan != nil || len(c.workChan) != 1 {
		t.Errorf("bruteChan=%v, shared lane holds %d; want no lane and the item shared", c.bruteChan != nil, len(c.workChan))
	}
}

func testWordlistTask() *WordlistTask {
	return NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   payload.NewLazyCustomProviderFromInline("t", []string{"admin"}),
		SchemeHost: []byte("http://a.test"),
		Path:       []byte("/"),
	})
}
