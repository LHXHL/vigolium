package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

// DiskQueue implements Queue using LevelDB with segment rotation.
// Tasks are persisted to disk and survive server restarts.
type DiskQueue struct {
	baseDir          string
	maxRecordsPerSeg int

	// discardBefore drops (acks without delivering) any task created before
	// it. Zero = deliver everything. Set from DiscardOlderThan at open, so it
	// only ever catches tasks a previous run left behind.
	discardBefore time.Time
	// recovered is how many pending tasks were on disk at open.
	recovered int64
	discarded atomic.Int64

	segments      []*Segment // Ordered by ID (oldest first)
	activeSegment *Segment   // Current segment for writing
	nextSegmentID uint64

	closed    atomic.Bool
	closeChan chan struct{}
	cleanupWg conc.WaitGroup
	notify    chan struct{} // Signals Dequeue when new tasks arrive

	// taskSeg maps a dequeued task's ID → the segment it lives in, so Ack goes
	// straight to that segment instead of scanning every segment (the previous
	// O(segments) linear search). A stale mapping (segment reaped) falls back to
	// the linear scan.
	taskSeg sync.Map

	// Metrics
	totalEnqueued  atomic.Int64
	totalDequeued  atomic.Int64
	totalCompleted atomic.Int64
	enqueueErrors  atomic.Int64
	dequeueErrors  atomic.Int64

	mu sync.RWMutex
}

// DiskQueueConfig holds configuration for DiskQueue.
type DiskQueueConfig struct {
	// BaseDir is the root directory for queue storage.
	// Default: os.TempDir()/vigolium-queue
	BaseDir string

	// MaxRecordsPerSegment is the maximum tasks per segment before rotation.
	// Default: 10000
	MaxRecordsPerSegment int

	// DiscardOlderThan, when > 0, drops recovered tasks older than this at
	// dequeue instead of replaying them: a task a crashed server left behind
	// days ago targets a world that has moved on.
	DiscardOlderThan time.Duration
}

// DefaultDiskQueueConfig returns sensible defaults.
func DefaultDiskQueueConfig() DiskQueueConfig {
	return DiskQueueConfig{
		BaseDir:              filepath.Join(os.TempDir(), "vigolium-queue"),
		MaxRecordsPerSegment: 10000,
	}
}

// NewDiskQueue creates a new disk-based queue.
func NewDiskQueue(cfg DiskQueueConfig) (*DiskQueue, error) {
	if cfg.BaseDir == "" {
		cfg.BaseDir = filepath.Join(os.TempDir(), "vigolium-queue")
	}
	if cfg.MaxRecordsPerSegment <= 0 {
		cfg.MaxRecordsPerSegment = 10000
	}

	// Ensure base directory exists
	// 0700: queued tasks carry raw requests (cookies, tokens, bodies).
	if err := os.MkdirAll(cfg.BaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	q := &DiskQueue{
		baseDir:          cfg.BaseDir,
		maxRecordsPerSeg: cfg.MaxRecordsPerSegment,
		closeChan:        make(chan struct{}),
		notify:           make(chan struct{}, 1),
	}
	if cfg.DiscardOlderThan > 0 {
		q.discardBefore = time.Now().Add(-cfg.DiscardOlderThan)
	}

	// Load existing segments or create first one
	if err := q.loadOrCreateSegments(); err != nil {
		return nil, err
	}
	for _, seg := range q.segments {
		q.recovered += seg.PendingTasks()
	}

	// Start background cleanup goroutine
	q.cleanupWg.Go(func() {
		q.cleanupLoop()
	})

	zap.L().Info("DiskQueue initialized",
		zap.String("base_dir", cfg.BaseDir),
		zap.Int("max_per_segment", cfg.MaxRecordsPerSegment),
		zap.Int("loaded_segments", len(q.segments)))

	return q, nil
}

// loadOrCreateSegments loads existing segments from disk or creates the first one.
func (q *DiskQueue) loadOrCreateSegments() error {
	entries, err := os.ReadDir(q.baseDir)
	if err != nil {
		return fmt.Errorf("failed to read base directory: %w", err)
	}

	var maxID uint64 = 0
	var segmentDirs []string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "segment_") {
			continue
		}

		// Extract segment ID from name (segment_XXXXXXXX)
		idStr := strings.TrimPrefix(entry.Name(), "segment_")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			zap.L().Warn("Invalid segment directory name",
				zap.String("name", entry.Name()))
			continue
		}

		segmentDirs = append(segmentDirs, entry.Name())
		if id > maxID {
			maxID = id
		}
	}

	// Sort segment directories by name (which is by ID)
	sort.Strings(segmentDirs)

	// Open each segment
	for _, dir := range segmentDirs {
		segPath := filepath.Join(q.baseDir, dir)
		idStr := strings.TrimPrefix(dir, "segment_")
		id, _ := strconv.ParseUint(idStr, 10, 64)

		seg, err := OpenSegment(segPath, id)
		if err != nil {
			zap.L().Warn("Failed to open segment, skipping",
				zap.String("path", segPath),
				zap.Error(err))
			continue
		}

		// Check if segment can be deleted (all completed)
		if seg.CanDelete() {
			zap.L().Info("Deleting completed segment during load",
				zap.Uint64("segment_id", id))
			_ = seg.Delete()
			continue
		}

		q.segments = append(q.segments, seg)
	}

	q.nextSegmentID = maxID + 1

	// If no segments exist or all were deleted, create the first one
	if len(q.segments) == 0 {
		return q.createNewSegment()
	}

	// The last segment is the active one (if not sealed)
	lastSeg := q.segments[len(q.segments)-1]
	if !lastSeg.IsSealed() && lastSeg.TotalTasks() < int64(q.maxRecordsPerSeg) {
		q.activeSegment = lastSeg
	} else {
		// All existing segments are sealed, create new one
		if err := q.createNewSegment(); err != nil {
			return err
		}
	}

	return nil
}

// createNewSegment creates a new segment for writing.
func (q *DiskQueue) createNewSegment() error {
	seg, err := NewSegment(SegmentConfig{
		BaseDir: q.baseDir,
		ID:      q.nextSegmentID,
	})
	if err != nil {
		return err
	}

	q.segments = append(q.segments, seg)
	q.activeSegment = seg
	q.nextSegmentID++

	zap.L().Info("New segment created",
		zap.Uint64("segment_id", seg.ID()))

	return nil
}

// Enqueue adds a task to the queue.
func (q *DiskQueue) Enqueue(ctx context.Context, task *ScanTask) error {
	if q.closed.Load() {
		q.enqueueErrors.Add(1)
		return ErrQueueClosed
	}

	if !task.IsValid() {
		q.enqueueErrors.Add(1)
		return ErrInvalidTask
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Check context
	select {
	case <-ctx.Done():
		q.enqueueErrors.Add(1)
		return ctx.Err()
	case <-q.closeChan:
		q.enqueueErrors.Add(1)
		return ErrQueueClosed
	default:
	}

	// Check if active segment needs rotation
	if q.activeSegment == nil {
		q.enqueueErrors.Add(1)
		return ErrNoActiveSegment
	}

	if q.activeSegment.TotalTasks() >= int64(q.maxRecordsPerSeg) {
		// Seal current segment and create new one
		q.activeSegment.Seal()
		if err := q.createNewSegment(); err != nil {
			q.enqueueErrors.Add(1)
			return fmt.Errorf("failed to create new segment: %w", err)
		}
	}

	// Write task to active segment
	task.Status = TaskStatusPending
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}
	task.UpdatedAt = task.CreatedAt

	if err := q.activeSegment.WriteTask(task); err != nil {
		q.enqueueErrors.Add(1)
		return err
	}

	q.totalEnqueued.Add(1)

	// Wake up a blocked Dequeue caller
	select {
	case q.notify <- struct{}{}:
	default:
	}

	return nil
}

// EnqueueBatch enqueues multiple tasks efficiently using batch writes.
func (q *DiskQueue) EnqueueBatch(ctx context.Context, tasks []*ScanTask) error {
	if q.closed.Load() {
		return ErrQueueClosed
	}
	if len(tasks) == 0 {
		return nil
	}

	// Validate all tasks first
	for _, task := range tasks {
		if !task.IsValid() {
			return ErrInvalidTask
		}
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.closeChan:
		return ErrQueueClosed
	default:
	}

	if q.activeSegment == nil {
		return ErrNoActiveSegment
	}

	// Prepare tasks
	now := time.Now()
	for _, task := range tasks {
		task.Status = TaskStatusPending
		if task.CreatedAt.IsZero() {
			task.CreatedAt = now
		}
		task.UpdatedAt = task.CreatedAt
	}

	// Write in chunks no larger than the per-segment cap so an oversized batch
	// can't blow past maxRecordsPerSeg in a single segment. Each chunk runs the
	// same rotate-if-full check a normal batch does.
	chunkMax := q.maxRecordsPerSeg
	if chunkMax <= 0 {
		chunkMax = len(tasks)
	}
	for start := 0; start < len(tasks); start += chunkMax {
		end := start + chunkMax
		if end > len(tasks) {
			end = len(tasks)
		}
		chunk := tasks[start:end]

		// Rotate before writing when this chunk would fill/overflow the segment.
		if q.activeSegment.TotalTasks()+int64(len(chunk)) >= int64(q.maxRecordsPerSeg) {
			q.activeSegment.Seal()
			if err := q.createNewSegment(); err != nil {
				return fmt.Errorf("failed to create new segment: %w", err)
			}
		}

		if err := q.activeSegment.WriteTasks(chunk); err != nil {
			q.enqueueErrors.Add(int64(len(chunk)))
			return err
		}
		q.totalEnqueued.Add(int64(len(chunk)))
	}

	// Wake up blocked Dequeue callers
	select {
	case q.notify <- struct{}{}:
	default:
	}

	return nil
}

// Dequeue retrieves the next pending task.
// Blocks until a task is available or context is cancelled.
// Uses event-driven wakeup from Enqueue with a fallback ticker for recovery
// (e.g., pre-existing tasks on disk after restart).
func (q *DiskQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	// Try immediate dequeue first (non-blocking)
	task, err := q.tryDequeue()
	if err != nil {
		q.dequeueErrors.Add(1)
		return nil, err
	}
	if task != nil {
		q.totalDequeued.Add(1)
		return task, nil
	}

	// Block until signalled
	fallback := time.NewTicker(5 * time.Second)
	defer fallback.Stop()

	for {
		select {
		case <-ctx.Done():
			q.dequeueErrors.Add(1)
			return nil, ctx.Err()
		case <-q.closeChan:
			// Check for remaining tasks before returning EOF
			task, err := q.tryDequeue()
			if err != nil {
				return nil, io.EOF
			}
			if task != nil {
				return task, nil
			}
			return nil, io.EOF
		case <-q.notify:
			task, err := q.tryDequeue()
			if err != nil {
				q.dequeueErrors.Add(1)
				return nil, err
			}
			if task != nil {
				q.totalDequeued.Add(1)
				return task, nil
			}
		case <-fallback.C:
			task, err := q.tryDequeue()
			if err != nil {
				q.dequeueErrors.Add(1)
				return nil, err
			}
			if task != nil {
				q.totalDequeued.Add(1)
				return task, nil
			}
		}
	}
}

// tryDequeue attempts to get a pending task without blocking.
func (q *DiskQueue) tryDequeue() (*ScanTask, error) {
	// Check if queue is closed
	if q.closed.Load() {
		return nil, ErrQueueClosed
	}

	// Copy the segment slice under the lock — q.segments[:] would alias the
	// backing array, which createNewSegment (append) and cleanupCompletedSegments
	// (reassign) mutate concurrently, racing this range.
	q.mu.RLock()
	segments := make([]*Segment, len(q.segments))
	copy(segments, q.segments)
	q.mu.RUnlock()

	// Iterate from oldest segment first
	for _, seg := range segments {
		// Skip closed segments
		if seg.IsClosed() {
			continue
		}
		task, err := q.nextFreshPending(seg)
		if err != nil {
			zap.L().Warn("Error getting pending task from segment",
				zap.Uint64("segment_id", seg.ID()),
				zap.Error(err))
			continue
		}
		if task != nil {
			// Remember which segment owns this task so Ack can reach it directly.
			q.taskSeg.Store(task.ID, seg)
			return task, nil
		}
	}

	return nil, nil
}

// nextFreshPending returns seg's next pending task, acking (dropping) any that
// are older than the discard cutoff on the way.
func (q *DiskQueue) nextFreshPending(seg *Segment) (*ScanTask, error) {
	for {
		task, err := seg.GetNextPending()
		if err != nil || task == nil {
			return task, err
		}
		if q.discardBefore.IsZero() || !task.CreatedAt.Before(q.discardBefore) {
			return task, nil
		}
		if err := seg.AckTask(task.ID); err != nil && !errors.Is(err, ErrTaskNotFound) {
			return nil, err
		}
		if n := q.discarded.Add(1); n == 1 {
			zap.L().Warn("Discarding stale queued tasks left by a previous run",
				zap.Time("created_before", q.discardBefore))
		}
	}
}

// RecoveredTasks is how many pending tasks were on disk when the queue opened.
func (q *DiskQueue) RecoveredTasks() int64 { return q.recovered }

// DiscardedTasks is how many recovered tasks were dropped as stale so far.
func (q *DiskQueue) DiscardedTasks() int64 { return q.discarded.Load() }

// Ack marks a task as completed. It first tries the segment recorded for this
// task at dequeue (O(1)); if that mapping is missing or stale, it falls back to
// scanning every segment.
func (q *DiskQueue) Ack(taskID string) error {
	if v, ok := q.taskSeg.Load(taskID); ok {
		seg := v.(*Segment)
		err := seg.AckTask(taskID)
		q.taskSeg.Delete(taskID)
		if err == nil {
			q.totalCompleted.Add(1)
			return nil
		}
		if !errors.Is(err, ErrTaskNotFound) {
			return err
		}
		// Stale mapping (segment reaped, or task moved) — fall through to the scan.
	}

	// Fallback linear scan. Copy under the lock (see tryDequeue) to avoid racing
	// concurrent mutations of q.segments.
	q.mu.RLock()
	segments := make([]*Segment, len(q.segments))
	copy(segments, q.segments)
	q.mu.RUnlock()

	for _, seg := range segments {
		err := seg.AckTask(taskID)
		if err == nil {
			q.totalCompleted.Add(1)
			return nil
		}
		if !errors.Is(err, ErrTaskNotFound) {
			return err
		}
	}

	return ErrTaskNotFound
}

// cleanupLoop periodically checks for and removes completed segments.
func (q *DiskQueue) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.closeChan:
			return
		case <-ticker.C:
			q.cleanupCompletedSegments()
		}
	}
}

// cleanupCompletedSegments removes segments where all tasks are completed.
func (q *DiskQueue) cleanupCompletedSegments() {
	q.mu.Lock()
	defer q.mu.Unlock()

	var remaining []*Segment
	for _, seg := range q.segments {
		// Don't delete the active segment even if empty
		if seg == q.activeSegment {
			remaining = append(remaining, seg)
			continue
		}

		if seg.CanDelete() {
			if err := seg.Delete(); err != nil {
				zap.L().Warn("Failed to delete completed segment",
					zap.Uint64("segment_id", seg.ID()),
					zap.Error(err))
				remaining = append(remaining, seg)
			}
		} else {
			remaining = append(remaining, seg)
		}
	}

	q.segments = remaining
}

// Close releases resources.
func (q *DiskQueue) Close() error {
	if !q.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	close(q.closeChan)

	// Wait for cleanup goroutine to finish
	func() {
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("DiskQueue: panic in cleanup goroutine", zap.Any("panic", r))
			}
		}()
		q.cleanupWg.Wait()
	}()

	q.mu.Lock()
	defer q.mu.Unlock()

	var lastErr error
	for _, seg := range q.segments {
		if err := seg.Close(); err != nil {
			lastErr = err
			zap.L().Warn("Failed to close segment",
				zap.Uint64("segment_id", seg.ID()),
				zap.Error(err))
		}
	}

	zap.L().Info("DiskQueue closed",
		zap.Int64("total_enqueued", q.totalEnqueued.Load()),
		zap.Int64("total_dequeued", q.totalDequeued.Load()),
		zap.Int64("total_completed", q.totalCompleted.Load()))

	return lastErr
}

// Metrics returns current queue statistics.
func (q *DiskQueue) Metrics() *QueueMetrics {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var depth int64
	var diskUsage int64
	for _, seg := range q.segments {
		depth += seg.PendingTasks()
		diskUsage += seg.CachedDiskSize()
	}

	return &QueueMetrics{
		Depth:          depth,
		TotalEnqueued:  q.totalEnqueued.Load(),
		TotalDequeued:  q.totalDequeued.Load(),
		TotalCompleted: q.totalCompleted.Load(),
		EnqueueErrors:  q.enqueueErrors.Load(),
		DequeueErrors:  q.dequeueErrors.Load(),
		SegmentCount:   len(q.segments),
		DiskUsageBytes: diskUsage,
	}
}

// SaveMetadata saves queue metadata to disk for recovery.
func (q *DiskQueue) SaveMetadata() error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	metadata := struct {
		NextSegmentID uint64 `json:"next_segment_id"`
		SegmentCount  int    `json:"segment_count"`
		UpdatedAt     string `json:"updated_at"`
	}{
		NextSegmentID: q.nextSegmentID,
		SegmentCount:  len(q.segments),
		UpdatedAt:     time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	metadataPath := filepath.Join(q.baseDir, "metadata.json")
	return os.WriteFile(metadataPath, data, 0644)
}
