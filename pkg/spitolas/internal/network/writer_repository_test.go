package network

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// fakeRecordSaver records everything handed to it so tests can assert the async
// RepositoryWriter batches and flushes correctly.
//
// The optional knobs (block, failAll) let the lifecycle tests in
// writer_admission_test.go simulate a stalled or failing database without a
// second RecordSaver implementation — one fake per interface, so a signature
// change has one place to follow.
type fakeRecordSaver struct {
	mu           sync.Mutex
	singleCalls  int
	batchCalls   int
	savedRecords int
	// block, when non-nil, parks every batch save until it is closed or the
	// save's own context expires.
	block chan struct{}
	// failAll makes every batch fail, exercising the drop-accounting path.
	failAll bool
	// sawDeadline records whether the context handed to SaveRecordBatch carried
	// one — the thing that keeps the drainer making progress.
	sawDeadline bool
}

func (f *fakeRecordSaver) SaveRecord(_ context.Context, _ *httpmsg.HttpRequestResponse, _ string, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.singleCalls++
	f.savedRecords++
	return "id", nil
}

func (f *fakeRecordSaver) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, _ string, _ string) ([]string, error) {
	_, hasDeadline := ctx.Deadline()

	f.mu.Lock()
	f.batchCalls++
	if hasDeadline {
		f.sawDeadline = true
	}
	block, failAll := f.block, f.failAll
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if failAll {
		return nil, errors.New("simulated database failure")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.savedRecords += len(records)
	ids := make([]string, len(records))
	for i := range ids {
		ids[i] = "id"
	}
	return ids, nil
}

func (f *fakeRecordSaver) counts() (single, batch, saved int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.singleCalls, f.batchCalls, f.savedRecords
}

// unblock releases a saver parked on its block channel.
func (f *fakeRecordSaver) unblock() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.block != nil {
		close(f.block)
		f.block = nil
	}
}

// deadlineSeen reports whether any batch save received a bounded context.
func (f *fakeRecordSaver) deadlineSeen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawDeadline
}

// TestRepositoryWriterFlushesAllOnClose verifies every written record is persisted
// by the time Close() returns, that persistence goes through SaveRecordBatch (not
// one-at-a-time SaveRecord), and that Count() reflects the flushed records.
func TestRepositoryWriterFlushesAllOnClose(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "spidering", "proj")

	const n = 150 // > writerBatchSize so at least one size-triggered flush happens
	for i := 0; i < n; i++ {
		entry := createTestEntry("https://example.com/page" + string(rune('a'+i%26)) + itoa(i))
		if err := w.Write(entry); err != nil {
			t.Fatalf("Write %d returned error: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	single, batch, saved := saver.counts()
	if single != 0 {
		t.Errorf("expected 0 single SaveRecord calls (async writer must batch), got %d", single)
	}
	if batch == 0 {
		t.Errorf("expected at least one SaveRecordBatch call, got 0")
	}
	if saved != n {
		t.Errorf("expected %d records persisted by Close(), got %d", n, saved)
	}
	if w.Count() != n {
		t.Errorf("expected Count()=%d, got %d", n, w.Count())
	}
}

// TestRepositoryWriterScopeFilterDrops verifies out-of-scope records never reach
// the saver, and Close remains safe to call twice.
func TestRepositoryWriterScopeFilterDrops(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "spidering", "proj")
	w.ScopeFilter = func(host, _ string) bool { return host == "in.example.com" }

	_ = w.Write(createTestEntry("https://in.example.com/keep"))
	_ = w.Write(createTestEntry("https://out.example.com/drop"))

	if err := w.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	// Idempotent Close must not panic or deadlock.
	if err := w.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	if _, _, saved := saver.counts(); saved != 1 {
		t.Errorf("expected 1 in-scope record persisted, got %d", saved)
	}
}

// itoa is a tiny int→string helper so the test avoids importing strconv purely for
// building distinct URLs (each entry must hash distinctly to avoid dedup upstream).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
