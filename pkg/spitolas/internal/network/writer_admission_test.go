package network

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withShortWriterBudgets temporarily shrinks the writer's shutdown budgets and
// restores them at test end. Tests that assert shutdown bounds use this instead
// of the 30s production values so they stay fast without stubbing out the timing
// logic they exist to check.
func withShortWriterBudgets(t *testing.T, save, drain time.Duration) {
	t.Helper()
	origSave, origDrain := writerSaveTimeout, writerDrainTimeout
	writerSaveTimeout, writerDrainTimeout = save, drain
	t.Cleanup(func() { writerSaveTimeout, writerDrainTimeout = origSave, origDrain })
}

// admissionEntry builds a distinct, cleanly-converting entry per index so nothing
// dedups upstream.
func admissionEntry(i int) *TrafficEntry {
	return createTestEntry("https://example.com/admit/" + itoa(i))
}

// TestWriterCloseReportsDroppedRecords pins the accounting half: Close used to
// return nil unconditionally, so a crawl whose every batch failed reported
// success at the one place a caller could have checked.
func TestWriterCloseReportsDroppedRecords(t *testing.T) {
	saver := &fakeRecordSaver{failAll: true}
	w := NewRepositoryWriter(saver, "test", "project-uuid")

	for i := range 3 {
		if err := w.Write(admissionEntry(i)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if err := w.Close(); err == nil {
		t.Fatal("Close returned nil after every batch failed; a total loss must be " +
			"distinguishable from a clean run")
	}
	if got := w.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0", got)
	}
}

// TestWriteAfterCloseIsRefusedNotSilentlyDropped pins the admission race. The old
// `select { case queue <- item; case <-stop }` let a late write land in the queue
// after the drainer had exited whenever both cases were ready — Go picks among
// ready cases at random — and returned nil for a record nothing would ever
// persist. The barrier makes the refusal explicit and total.
func TestWriteAfterCloseIsRefusedNotSilentlyDropped(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "test", "project-uuid")

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The queue is empty (so a send would succeed) and stop is closed: exactly the
	// state where the old select was a coin flip.
	for i := range 50 {
		if err := w.Write(admissionEntry(i)); !errors.Is(err, ErrWriterClosed) {
			t.Fatalf("Write #%d after Close = %v, want ErrWriterClosed", i, err)
		}
	}

	if _, _, saved := saver.counts(); saved != 0 {
		t.Errorf("%d record(s) were persisted after Close", saved)
	}
}

// TestConcurrentWriteAndCloseAdmitsOrRefuses is the same contract under real
// concurrency: every Write either returns nil (and is persisted) or returns
// ErrWriterClosed. There is no third outcome where nil is returned for a record
// that is then lost.
func TestConcurrentWriteAndCloseAdmitsOrRefuses(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "test", "project-uuid")

	const writers, perWriter = 16, 20
	var admitted, refused atomic.Int64

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := range perWriter {
				err := w.Write(admissionEntry(i*perWriter + j))
				switch {
				case err == nil:
					admitted.Add(1)
				case errors.Is(err, ErrWriterClosed):
					refused.Add(1)
				default:
					t.Errorf("unexpected Write error: %v", err)
				}
			}
		}(i)
	}

	close(start)
	time.Sleep(5 * time.Millisecond) // let some writes land before closing
	closeErr := w.Close()
	wg.Wait()

	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if admitted.Load()+refused.Load() != writers*perWriter {
		t.Fatalf("accounting lost writes: admitted=%d refused=%d want total %d",
			admitted.Load(), refused.Load(), writers*perWriter)
	}
	// Every admitted record must have been persisted — that is the promise a nil
	// return makes.
	if _, _, saved := saver.counts(); int64(saved) != admitted.Load() {
		t.Errorf("admitted %d records but persisted %d; a nil Write return must mean "+
			"the record reached the drainer", admitted.Load(), saved)
	}
}

// TestCaptureCloseIsNotBlockedByAnInFlightWrite is the deadlock regression, and
// it asserts the invariant directly rather than trying to stage the full stall.
//
// writeEntry used to call writer.Write while holding c.mu. Write blocks when the
// persistence queue is full, and Capture.Close needs that same mutex to set
// c.stopped and reach writer.Close — which is the only thing that can drain the
// queue the write is waiting on. A stalled database therefore wedged the capture
// permanently, with no way to shut the crawl down.
//
// Staging that end-to-end is a bad test: the bounded save context (added in the
// same change) lets even the buggy version recover eventually, so any wall-clock
// assertion measures the timeout rather than the lock. The invariant that
// actually distinguishes the two is narrow and immediate — Capture.Close must
// make progress while a writeEntry is parked inside writer.Write.
func TestCaptureCloseIsNotBlockedByAnInFlightWrite(t *testing.T) {
	// A Writer that parks inside Write until the test releases it.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	bw := &blockingWriter{
		onWrite: func() {
			once.Do(func() { close(entered) })
			<-release
		},
	}
	c := New(bw, true, true, false, false, false, "example.com", "test")

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		c.writeEntry(admissionEntry(1))
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("writeEntry never reached writer.Write")
	}

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(release) // unwedge so the test can exit cleanly
		t.Fatal("Capture.Close blocked while a writeEntry was inside writer.Write — " +
			"writeEntry is holding c.mu across the write again, which is the deadlock: " +
			"Close needs that mutex to reach the writer that would drain the queue")
	}

	close(release)
	<-writeDone
}

// blockingWriter runs onWrite inside Write, letting a test park a producer.
type blockingWriter struct{ onWrite func() }

func (b *blockingWriter) Write(*TrafficEntry) error {
	b.onWrite()
	return nil
}

func (b *blockingWriter) Close() error { return nil }

// TestCaptureCloseIsBoundedUnderAStalledSaver covers the end-to-end shutdown
// bound with the real RepositoryWriter: producers piled against a full queue, a
// saver that never answers, and Close still returning within
// writerSaveTimeout + writerDrainTimeout. The budgets are shrunk rather than
// stubbed so the production code path is the one exercised.
func TestCaptureCloseIsBoundedUnderAStalledSaver(t *testing.T) {
	withShortWriterBudgets(t, 500*time.Millisecond, 500*time.Millisecond)

	saver := &fakeRecordSaver{block: make(chan struct{})}
	w := NewRepositoryWriter(saver, "test", "project-uuid")
	c := New(w, true, true, false, false, false, "example.com", "test")

	// Fill well past the queue so producers are blocked on a stalled saver.
	producers := make(chan struct{})
	var producing sync.WaitGroup
	for i := range writerQueueSize + 64 {
		producing.Add(1)
		go func(i int) {
			defer producing.Done()
			<-producers
			c.writeEntry(admissionEntry(i))
		}(i)
	}
	close(producers)

	// Give the producers time to pile up against the full queue.
	time.Sleep(100 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()

	// The documented bound: one in-flight batch, then one final drain.
	bound := writerSaveTimeout + writerDrainTimeout
	select {
	case <-closed:
		// Close got through while the saver was still stalled, which is the point.
	case <-time.After(bound + 5*time.Second):
		t.Fatalf("Capture.Close did not return within %s of a stalled saver", bound)
	}

	saver.unblock()
	producing.Wait()

	if !saver.deadlineSeen() {
		t.Error("SaveRecordBatch was called without a deadline; an unbounded save " +
			"stalls the drainer and re-opens the shutdown deadlock")
	}
}

// TestWriterSaveContextIsBounded pins the deadline in isolation, so the reason
// for it is not lost if the deadlock test above is ever rewritten.
func TestWriterSaveContextIsBounded(t *testing.T) {
	saver := &fakeRecordSaver{}
	w := NewRepositoryWriter(saver, "test", "project-uuid")

	if err := w.Write(admissionEntry(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, batch, _ := saver.counts(); batch == 0 {
		t.Fatal("no batch save happened")
	}
	if !saver.deadlineSeen() {
		t.Error("SaveRecordBatch received a context with no deadline; it must be " +
			"bounded by writerSaveTimeout so the drainer always makes progress")
	}
}
