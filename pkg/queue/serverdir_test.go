package queue

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Enqueue, close without draining, reopen the same keyed dir: the tasks are
// still there and are reported as recovered.
func TestServerQueueDirRecoversQueuedTasks(t *testing.T) {
	root := t.TempDir()
	d, err := OpenServerQueueDir(root, "sqlite:/tmp/a.sqlite", false)
	require.NoError(t, err)
	assert.False(t, d.Fallback)

	q, err := NewDiskQueue(DiskQueueConfig{BaseDir: d.Path})
	require.NoError(t, err)
	for i := range 3 {
		require.NoError(t, q.Enqueue(context.Background(), NewScanTask(fmt.Sprintf("https://t/%d", i), "GET / HTTP/1.1\r\n\r\n", nil)))
	}
	require.NoError(t, q.Close())
	d.Release(false)
	assert.DirExists(t, d.Path, "a non-empty queue keeps its directory")

	d2, err := OpenServerQueueDir(root, "sqlite:/tmp/a.sqlite", false)
	require.NoError(t, err)
	defer d2.Release(true)
	assert.Equal(t, d.Path, d2.Path, "same database → same directory")
	q2, err := NewDiskQueue(DiskQueueConfig{BaseDir: d2.Path})
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()
	assert.Equal(t, int64(3), q2.RecoveredTasks())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	task, err := q2.Dequeue(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://t/0", task.URL)
}

// --discard-queued empties the directory before the queue opens.
func TestServerQueueDirDiscard(t *testing.T) {
	root := t.TempDir()
	d, err := OpenServerQueueDir(root, "db", false)
	require.NoError(t, err)
	q, err := NewDiskQueue(DiskQueueConfig{BaseDir: d.Path})
	require.NoError(t, err)
	require.NoError(t, q.Enqueue(context.Background(), NewScanTask("https://t/", "GET / HTTP/1.1\r\n\r\n", nil)))
	require.NoError(t, q.Close())
	d.Release(false)

	d2, err := OpenServerQueueDir(root, "db", true)
	require.NoError(t, err)
	defer d2.Release(true)
	q2, err := NewDiskQueue(DiskQueueConfig{BaseDir: d2.Path})
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()
	assert.Equal(t, int64(0), q2.RecoveredTasks())
}

// Recovered tasks older than the cutoff are dropped, not replayed.
func TestDiskQueueDiscardsStaleRecoveredTasks(t *testing.T) {
	dir := t.TempDir()
	q, err := NewDiskQueue(DiskQueueConfig{BaseDir: dir})
	require.NoError(t, err)
	old := NewScanTask("https://t/old", "GET / HTTP/1.1\r\n\r\n", nil)
	old.CreatedAt = time.Now().Add(-48 * time.Hour)
	require.NoError(t, q.Enqueue(context.Background(), old))
	require.NoError(t, q.Enqueue(context.Background(), NewScanTask("https://t/fresh", "GET / HTTP/1.1\r\n\r\n", nil)))
	require.NoError(t, q.Close())

	q2, err := NewDiskQueue(DiskQueueConfig{BaseDir: dir, DiscardOlderThan: 24 * time.Hour})
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	task, err := q2.Dequeue(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://t/fresh", task.URL)
	assert.Equal(t, int64(1), q2.DiscardedTasks())
}

// A second server on the same database gets a PID-suffixed sibling instead of
// contending for the lock, and that sibling is removed on release.
func TestServerQueueDirLockContentionFallsBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no flock")
	}
	root := t.TempDir()
	first, err := OpenServerQueueDir(root, "db", false)
	require.NoError(t, err)
	defer first.Release(true)

	second, err := OpenServerQueueDir(root, "db", false)
	require.NoError(t, err)
	assert.True(t, second.Fallback)
	assert.Equal(t, fmt.Sprintf("%s-%d", first.Path, os.Getpid()), second.Path)
	second.Release(false)
	assert.NoDirExists(t, second.Path, "a fallback dir is never resumed, so it is removed")
	assert.DirExists(t, first.Path)
}

// The legacy sweep removes only directories whose PID is dead.
func TestSweepLegacyServerQueuesOnlyDeadPIDs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no liveness probe")
	}
	tmp, root := t.TempDir(), t.TempDir()
	deadPID := 1 << 22 // above any default pid_max
	live := filepath.Join(tmp, fmt.Sprintf("%s%d", LegacyServerQueuePrefix, os.Getppid()))
	dead := filepath.Join(tmp, fmt.Sprintf("%s%d", LegacyServerQueuePrefix, deadPID))
	other := filepath.Join(tmp, "unrelated-123")
	deadFallback := filepath.Join(root, fmt.Sprintf("0123456789abcdef-%d", deadPID))
	keyed := filepath.Join(root, "0123456789abcdef")
	for _, d := range []string{live, dead, other, deadFallback, keyed} {
		require.NoError(t, os.MkdirAll(d, 0o700))
	}

	assert.Equal(t, 2, SweepLegacyServerQueues(tmp, root))
	assert.DirExists(t, live)
	assert.NoDirExists(t, dead)
	assert.DirExists(t, other)
	assert.NoDirExists(t, deadFallback)
	assert.DirExists(t, keyed)
}

func TestServerQueueDirPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	d, err := OpenServerQueueDir(t.TempDir(), "db", false)
	require.NoError(t, err)
	defer d.Release(true)
	info, err := os.Stat(d.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}
