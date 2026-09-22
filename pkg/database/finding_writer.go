package database

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// FindingWriterConfig configures the batching behavior of FindingWriter.
type FindingWriterConfig struct {
	// BufferSize is the channel capacity. When full, Save persists inline rather
	// than blocking the scan worker. Default: 1024.
	BufferSize int

	// BatchSize is the maximum number of findings coalesced into one transaction.
	// Default: 64.
	BatchSize int

	// FlushInterval is the maximum time a finding waits in the buffer before
	// being flushed, even if the batch isn't full. Default: 50ms.
	FlushInterval time.Duration

	// FlushTimeout bounds the shutdown drain so a wedged database can't block
	// Close() forever. Steady-state flushes use an uncancellable context.
	// Default: 2m.
	FlushTimeout time.Duration
}

func (c *FindingWriterConfig) withDefaults() FindingWriterConfig {
	out := *c
	if out.BufferSize <= 0 {
		out.BufferSize = 1024
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 64
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 50 * time.Millisecond
	}
	if out.FlushTimeout <= 0 {
		out.FlushTimeout = 2 * time.Minute
	}
	return out
}

// findingWrite is a single queued finding.
type findingWrite struct {
	event       *output.ResultEvent
	recordUUIDs []string
	scanUUID    string
	projectUUID string
}

// FindingWriterMetrics exposes counters for monitoring.
type FindingWriterMetrics struct {
	Enqueued int64 // findings handed to the background writer
	Written  int64 // findings persisted by the background writer
	Inline   int64 // findings persisted synchronously (buffer full / shutting down)
	Errors   int64 // findings in a flush that ultimately failed to persist
}

// FindingWriter decouples finding persistence from scan workers. SaveFinding is
// a multi-statement, dedup-aware operation; calling it synchronously on every
// worker blocks the worker on a database round-trip. FindingWriter funnels
// findings through a single background goroutine that coalesces them into batch
// transactions (one fsync for many findings) via Repository.SaveFindingsBatch.
//
// Findings are low-volume relative to HTTP records, so a single writer goroutine
// keeps up while also eliminating write contention between concurrent finding
// transactions. This mirrors RecordWriter's lifecycle (buffered channel,
// background flush, bounded shutdown drain) but is fire-and-forget: the result
// UUID is never needed by the caller, so Save does not block on persistence.
type FindingWriter struct {
	repo *Repository
	cfg  FindingWriterConfig
	ch   chan findingWrite

	// mu guards the closed flag against concurrent channel sends so Close can
	// guarantee no send is in flight when it stops accepting new findings.
	mu     sync.RWMutex
	closed bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	enqueued atomic.Int64
	written  atomic.Int64
	inline   atomic.Int64
	errors   atomic.Int64
}

// NewFindingWriter creates and starts a FindingWriter. Call Close() to flush
// remaining findings and stop the background goroutine.
func NewFindingWriter(repo *Repository, cfg FindingWriterConfig) *FindingWriter {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())

	w := &FindingWriter{
		repo:   repo,
		cfg:    cfg,
		ch:     make(chan findingWrite, cfg.BufferSize),
		ctx:    ctx,
		cancel: cancel,
	}

	w.wg.Add(1)
	go w.flushLoop()

	return w
}

// Save enqueues a finding for batched persistence. It does not block on the
// database: if the buffer is full or the writer is shutting down, the finding is
// persisted synchronously so nothing is dropped. Safe for concurrent callers.
func (w *FindingWriter) Save(ctx context.Context, event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}
	fw := findingWrite{event: event, recordUUIDs: recordUUIDs, scanUUID: scanUUID, projectUUID: projectUUID}

	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		w.inline.Add(1)
		return w.repo.SaveFinding(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
	// The non-blocking send happens under RLock so Close (which takes the write
	// lock before cancelling) can never race a send against the drain shutdown.
	select {
	case w.ch <- fw:
		w.mu.RUnlock()
		w.enqueued.Add(1)
		return nil
	default:
		w.mu.RUnlock()
		// Buffer full — persist inline rather than blocking the worker or
		// dropping the finding. Rare for low-volume findings.
		w.inline.Add(1)
		return w.repo.SaveFinding(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
}

// Metrics returns a snapshot of the writer's counters.
func (w *FindingWriter) Metrics() FindingWriterMetrics {
	return FindingWriterMetrics{
		Enqueued: w.enqueued.Load(),
		Written:  w.written.Load(),
		Inline:   w.inline.Load(),
		Errors:   w.errors.Load(),
	}
}

// Close stops accepting new findings, flushes the buffer, and returns. After
// Close, Save persists synchronously. The drain is bounded by FlushTimeout so a
// wedged database can't hang Close forever.
func (w *FindingWriter) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	// No send can be in flight now (Save holds RLock during its send, and we
	// hold the write lock above until all such sends complete), and no new send
	// will start because Save sees closed==true. Safe to wake the drain.
	w.cancel()
	w.wg.Wait()

	// Surface fire-and-forget persistence failures at shutdown. Save returns nil
	// as soon as a finding is enqueued, so a later batch failure is otherwise
	// invisible — the scan would complete reporting success while silently having
	// dropped findings. This warning lands in the scan's captured stderr/log.
	if failed := w.errors.Load(); failed > 0 {
		zap.L().Warn("FindingWriter: some findings failed to persist and were dropped",
			zap.Int64("dropped_findings", failed),
			zap.Int64("written", w.written.Load()),
			zap.Int64("enqueued", w.enqueued.Load()))
	}
}

// flushLoop drains the channel and coalesces findings into batch transactions.
// Steady-state flushes use context.Background() so a slow insert never aborts
// mid-flush; only the shutdown drain is bounded (by FlushTimeout).
func (w *FindingWriter) flushLoop() {
	defer w.wg.Done()

	batch := make([]findingWrite, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case fw := <-w.ch:
			batch = append(batch, fw)
			if len(batch) >= w.cfg.BatchSize {
				w.flush(context.Background(), batch)
				batch = resetFindingBatch(batch)
				ticker.Reset(w.cfg.FlushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(context.Background(), batch)
				batch = resetFindingBatch(batch)
			}

		case <-w.ctx.Done():
			drainCtx, cancel := context.WithTimeout(context.Background(), w.cfg.FlushTimeout)
			for {
				select {
				case fw := <-w.ch:
					batch = append(batch, fw)
					if len(batch) >= w.cfg.BatchSize {
						w.flush(drainCtx, batch)
						batch = resetFindingBatch(batch)
					}
				default:
					if len(batch) > 0 {
						w.flush(drainCtx, batch)
					}
					cancel()
					return
				}
			}
		}
	}
}

// resetFindingBatch empties a flushed batch for reuse, clearing the entries
// first. This mirrors resetBatch in record_writer.go, for the same reason: a
// plain batch[:0] leaves the backing array's pointers live, so after a flush the
// loop still pins up to BatchSize findings — each one a *output.ResultEvent
// holding the full request, response and additional evidence that produced it.
// Findings are low-volume, so the writer is idle most of the time, and that is
// exactly when the stale retention lasts longest.
func resetFindingBatch(batch []findingWrite) []findingWrite {
	clear(batch)
	return batch[:0]
}

// flush persists a batch of findings in a single transaction.
func (w *FindingWriter) flush(ctx context.Context, batch []findingWrite) {
	writes := make([]FindingWrite, len(batch))
	for i, b := range batch {
		writes[i] = FindingWrite{
			Event:           b.event,
			HTTPRecordUUIDs: b.recordUUIDs,
			ScanUUID:        b.scanUUID,
			ProjectUUID:     b.projectUUID,
		}
	}

	// SaveFindingsBatch already retries per-finding on a transaction failure; a
	// returned error means at least one finding could not be persisted at all.
	if err := w.repo.SaveFindingsBatch(ctx, writes); err != nil {
		w.errors.Add(int64(len(batch)))
		zap.L().Warn("FindingWriter: batch flush failed",
			zap.Int("batch_size", len(batch)),
			zap.Error(err))
		return
	}
	w.written.Add(int64(len(batch)))
}
