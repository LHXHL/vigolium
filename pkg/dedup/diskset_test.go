package dedup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// newTestDiskSet builds a DiskSet rooted in a per-test temp dir so cleanup is
// automatic via t.TempDir(). Cleanup:false leaves removal to the test harness.
func newTestDiskSet(t *testing.T) *DiskSet {
	t.Helper()
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false})
	require.NoError(t, err)
	require.NotNil(t, ds)
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

// TestDiskSet_IsSeen_FirstSeenThenRepeat is the central dedup behavior: a key
// is "not seen" the first time (and gets recorded) and "seen" every time after.
func TestDiskSet_IsSeen_FirstSeenThenRepeat(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.False(t, ds.IsSeen("alpha"), "first sighting must report not-seen")
	assert.True(t, ds.IsSeen("alpha"), "repeat sighting must report seen")
	assert.True(t, ds.IsSeen("alpha"), "still seen on third sighting")

	// A distinct key is independent.
	assert.False(t, ds.IsSeen("beta"), "a different key is its own first sighting")
}

// TestDiskSet_SizeAndHits verifies the running counters: Size counts unique
// first-sightings, Hits counts duplicate sightings.
func TestDiskSet_SizeAndHits(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.Equal(t, int64(0), ds.Size())
	assert.Equal(t, uint64(0), ds.Hits())

	ds.IsSeen("a") // unique  -> size 1
	ds.IsSeen("b") // unique  -> size 2
	ds.IsSeen("a") // dup     -> hit 1
	ds.IsSeen("a") // dup     -> hit 2
	ds.IsSeen("c") // unique  -> size 3

	assert.Equal(t, int64(3), ds.Size(), "three distinct keys recorded")
	assert.Equal(t, uint64(2), ds.Hits(), "two duplicate sightings counted")
}

// TestDiskSet_Contains is a read-only membership check that must NOT record the
// key — i.e. probing a key with Contains leaves a later IsSeen reporting
// not-seen.
func TestDiskSet_Contains(t *testing.T) {
	ds := newTestDiskSet(t)

	assert.False(t, ds.Contains("ghost"), "absent key is not contained")
	assert.False(t, ds.IsSeen("ghost"), "Contains must not have recorded the key")

	// IsSeen now recorded it, so Contains sees it.
	assert.True(t, ds.Contains("ghost"), "key present after IsSeen records it")
}

// TestDiskSet_IncrementAndCheck verifies the counter fires at the configured
// limit: shouldContinue stays true while count <= limit and flips false once it
// exceeds.
func TestDiskSet_IncrementAndCheck(t *testing.T) {
	ds := newTestDiskSet(t)
	const limit = 3

	tests := []struct {
		wantCount    int
		wantContinue bool
	}{
		{1, true},
		{2, true},
		{3, true},  // exactly at limit still continues
		{4, false}, // exceeds limit -> stop
		{5, false},
	}
	for i, tc := range tests {
		count, cont := ds.IncrementAndCheck("counter-key", limit)
		assert.Equalf(t, tc.wantCount, count, "call %d count", i)
		assert.Equalf(t, tc.wantContinue, cont, "call %d shouldContinue", i)
	}

	// A different key keeps its own independent count.
	count, cont := ds.IncrementAndCheck("other-key", limit)
	assert.Equal(t, 1, count)
	assert.True(t, cont)
}

// TestDiskSet_Close_BehavesAfterClose documents post-Close behavior: IsSeen
// returns true (already-seen, to halt processing) and Contains returns false.
func TestDiskSet_Close_BehavesAfterClose(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false})
	require.NoError(t, err)

	ds.IsSeen("x")
	require.NoError(t, ds.Close())

	assert.True(t, ds.IsSeen("x"), "closed set treats everything as seen")
	assert.False(t, ds.Contains("x"), "closed set Contains returns false")
	count, cont := ds.IncrementAndCheck("x", 10)
	assert.Equal(t, 0, count)
	assert.False(t, cont, "closed set must not allow continuation")

	// Close is idempotent.
	assert.NoError(t, ds.Close())
}

// TestDiskSet_Cleanup_RemovesPath verifies Cleanup:true wipes the on-disk store
// on Close, while Cleanup:false leaves it.
func TestDiskSet_Cleanup_RemovesPath(t *testing.T) {
	path := t.TempDir() + "/cleanup-store"
	ds, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: true})
	require.NoError(t, err)
	ds.IsSeen("k")
	require.DirExists(t, path)

	require.NoError(t, ds.Close())
	assert.NoDirExists(t, path, "Cleanup:true must remove the store directory")
}

// TestDiskSet_DefaultPath_StaysOffDiskUntilSpill confirms an empty Path costs
// nothing on disk until the set outgrows its memory tier.
//
// Sets are per module, so eager provisioning made a probe of ONE host pay
// seventeen os.MkdirTemp + LevelDB open + manifest fsync + RemoveAll cycles for
// a handful of fingerprints that never came close to needing a database.
func TestDiskSet_DefaultPath_StaysOffDiskUntilSpill(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Cleanup: true}) // empty Path
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	ds.IsSeen("one")
	ds.IsSeen("two")
	assert.Empty(t, ds.path, "a set this small must not touch the disk")
	assert.Nil(t, ds.db)

	// Dedup still works entirely in memory.
	assert.True(t, ds.IsSeen("one"))
	assert.True(t, ds.Contains("two"))
	assert.False(t, ds.Contains("three"))
}

// TestDiskSet_SpillsToDiskAndCleansUp confirms the set provisions its store on
// the first key past the memory tier, keeps every key it had already, and
// removes the directory on Close.
func TestDiskSet_SpillsToDiskAndCleansUp(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Cleanup: true, MaxKeys: -1})
	require.NoError(t, err)

	for i := 0; i <= memTierMaxKeys; i++ {
		ds.IsSeen("key-" + strconv.Itoa(i))
	}

	require.NotEmpty(t, ds.path, "the set must have spilled")
	require.DirExists(t, ds.path)
	require.NotNil(t, ds.db)
	assert.Nil(t, ds.mem, "the memory tier is released once it has been written out")

	// Nothing written before the spill may be lost: a dropped key is a
	// re-processed request, which is exactly what this set exists to prevent.
	assert.True(t, ds.IsSeen("key-0"), "a pre-spill key must survive the move")
	assert.True(t, ds.IsSeen("key-"+strconv.Itoa(memTierMaxKeys/2)))
	assert.True(t, ds.IsSeen("key-"+strconv.Itoa(memTierMaxKeys)))

	created := ds.path
	require.NoError(t, ds.Close())
	assert.NoDirExists(t, created)
}

// An explicit Path names a store the caller wants on disk, very likely one
// meant to outlive this process, so it is honoured immediately rather than
// waiting for a spill that may never come.
func TestDiskSet_ExplicitPathIsProvisionedEagerly(t *testing.T) {
	path := t.TempDir() + "/pinned-store"
	ds, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	assert.DirExists(t, path)
	assert.NotNil(t, ds.db)
	assert.Nil(t, ds.mem)
}

// IncrementAndCheck has to count identically in both tiers, since which one a
// set is on depends only on how much traffic it happened to see.
func TestDiskSet_IncrementAndCheckAcrossTiers(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Cleanup: true, MaxKeys: -1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	// In memory.
	for i := 1; i <= 3; i++ {
		count, ok := ds.IncrementAndCheck("counter", 3)
		assert.Equal(t, i, count)
		assert.True(t, ok)
	}
	count, ok := ds.IncrementAndCheck("counter", 3)
	assert.Equal(t, 4, count)
	assert.False(t, ok, "past the limit")
	require.Nil(t, ds.db, "counting alone must not spill")

	// Force the spill, then keep counting from where it left off.
	for i := 0; i <= memTierMaxKeys; i++ {
		ds.IsSeen("filler-" + strconv.Itoa(i))
	}
	require.NotNil(t, ds.db, "the set must have spilled")

	count, ok = ds.IncrementAndCheck("counter", 3)
	assert.Equal(t, 5, count, "the counter must carry across the spill")
	assert.False(t, ok)
}

// TestDiskSet_IsSeen_Concurrent stresses the atomic check-then-put: many
// goroutines racing on the same key must yield exactly one "not seen" and the
// rest "seen", with Size==1 and Hits==(n-1). Run under -race for the data-race
// guarantee.
func TestDiskSet_IsSeen_Concurrent(t *testing.T) {
	ds := newTestDiskSet(t)

	const n = 200
	var notSeen atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !ds.IsSeen("race-key") {
				notSeen.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), notSeen.Load(), "exactly one goroutine sees the key first")
	assert.Equal(t, int64(1), ds.Size(), "only one unique key recorded")
	assert.Equal(t, uint64(n-1), ds.Hits(), "every other sighting is a duplicate")
}

// TestDiskSet_IncrementAndCheck_Concurrent ensures concurrent increments never
// lose updates (final count equals the number of calls) and that exactly one
// goroutine observes each count value.
func TestDiskSet_IncrementAndCheck_Concurrent(t *testing.T) {
	ds := newTestDiskSet(t)

	const n = 150
	var wg sync.WaitGroup
	seen := make([]atomic.Bool, n+1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count, _ := ds.IncrementAndCheck("k", n*2) // limit high enough not to matter
			if count >= 1 && count <= n {
				seen[count].Store(true)
			}
		}()
	}
	wg.Wait()

	// Final increment must equal exactly n (no lost updates).
	final, _ := ds.IncrementAndCheck("k", n*2)
	assert.Equal(t, n+1, final, "no increments lost under concurrency")

	for c := 1; c <= n; c++ {
		assert.Truef(t, seen[c].Load(), "count value %d should have been observed exactly once", c)
	}
}

// TestDiskSet_MaxKeys_BoundsKeyspace verifies the size cap evicts so the set
// can't grow without limit. With a small MaxKeys, inserting many more distinct
// keys keeps Size at or below the cap (plus at most one eviction batch of
// headroom), and eviction is FN-safe (an evicted key reports not-seen again).
func TestDiskSet_MaxKeys_BoundsKeyspace(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false, MaxKeys: 100})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	for i := 0; i < 5000; i++ {
		ds.IsSeen(fmt.Sprintf("k-%d", i))
	}

	// Cap is 100; eviction fires once size exceeds it, dropping a batch. The set
	// must stay bounded well under the number of distinct keys inserted.
	assert.LessOrEqual(t, ds.Size(), int64(diskSetEvictBatch+100),
		"size must stay bounded by the cap, not grow to the 5000 distinct keys")
	assert.Less(t, ds.Size(), int64(5000), "the set must not retain every key")
}

// TestDiskSet_MaxKeys_DisabledIsUnbounded confirms a negative MaxKeys opts out
// of the cap (legacy unbounded behavior) — every distinct key is retained.
func TestDiskSet_MaxKeys_DisabledIsUnbounded(t *testing.T) {
	ds, err := NewDiskSet(DiskSetOptions{Path: t.TempDir(), Cleanup: false, MaxKeys: -1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	for i := 0; i < 500; i++ {
		ds.IsSeen(fmt.Sprintf("k-%d", i))
	}
	assert.Equal(t, int64(500), ds.Size(), "negative MaxKeys disables eviction")
}

// TestDiskSet_PersistsAcrossReopen verifies the store is durable: keys recorded
// before Close are still present when the same path is reopened.
func TestDiskSet_PersistsAcrossReopen(t *testing.T) {
	path := t.TempDir() + "/persist-store"

	ds1, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: false})
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		ds1.IsSeen(fmt.Sprintf("key-%d", i))
	}
	require.NoError(t, ds1.Close())

	ds2, err := NewDiskSet(DiskSetOptions{Path: path, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = ds2.Close() }()

	for i := 0; i < 5; i++ {
		assert.Truef(t, ds2.Contains(fmt.Sprintf("key-%d", i)), "key-%d must survive reopen", i)
	}
	assert.False(t, ds2.Contains("never-written"))
}

// TestDiskSet_SpillFailureIsNotRetried is the other side of
// TestDiskSet_SpillsToDiskAndCleansUp: when the disk refuses the store, the set
// must fall back to memory ONCE and stay there.
//
// The retry is what makes this worth a test. Every new key past the memory tier
// re-enters putLocked, so without the latch each one attempts a fresh
// os.MkdirTemp and LevelDB open — under the write lock, on the path every module
// sharing this set calls per response — against a disk that is still full. The
// warn count is the assertion because it counts spill attempts exactly: one per
// call to spillLocked.
func TestDiskSet_SpillFailureIsNotRetried(t *testing.T) {
	// Point the scratch root at a regular file so every attempt to create a
	// directory under it fails with ENOTDIR — a stand-in for the full or
	// read-only disk this guards against.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))
	t.Setenv("TMPDIR", blocked)

	logs, restore := captureWarnings()
	defer restore()

	ds, err := NewDiskSet(DiskSetOptions{Cleanup: true, MaxKeys: -1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	// Well past the threshold: each of these is a new key, so each one is an
	// opportunity to retry the spill.
	const extra = 2000
	for i := 0; i <= memTierMaxKeys+extra; i++ {
		ds.IsSeen("key-" + strconv.Itoa(i))
	}

	assert.Nil(t, ds.db, "the spill failed, so there must be no disk tier")
	assert.Empty(t, ds.path)
	assert.True(t, ds.spillFailed, "the failure must be latched")
	assert.Equal(t, 1, logs.count(), "the spill must be attempted once, not once per key")

	// Falling back is only acceptable because the set still dedups.
	assert.True(t, ds.IsSeen("key-0"), "a pre-threshold key must survive")
	assert.True(t, ds.IsSeen("key-"+strconv.Itoa(memTierMaxKeys+extra)), "a post-threshold key must be retained")
	assert.False(t, ds.Contains("never-added"))
	assert.Equal(t, int64(memTierMaxKeys+extra+1), ds.Size())
}

// warnCounter counts warn-level records emitted through the global logger.
type warnCounter struct {
	mu sync.Mutex
	n  int
}

func (w *warnCounter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *warnCounter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.n++
	w.mu.Unlock()
	return len(p), nil
}

func (w *warnCounter) Sync() error { return nil }

// captureWarnings redirects the global logger's warn output to a counter and
// returns a function restoring the previous logger.
func captureWarnings() (*warnCounter, func()) {
	c := &warnCounter{}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(c),
		zapcore.WarnLevel,
	)
	return c, zap.ReplaceGlobals(zap.New(core))
}
