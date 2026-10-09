package fsexport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A write that fails before its rename (a crash, a full disk, a refused rename)
// leaves the destination as it was: whole old content or nothing, never a
// truncated file, and no staging file behind.
func TestMirrorAtomicWriteNeverTruncates(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "0001.req")
	require.NoError(t, writeFileAtomic(dst, []byte("complete original"), mirrorFileMode))
	require.NoError(t, writeFileAtomic(dst, []byte("complete replacement"), mirrorFileMode))
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "complete replacement", string(got))

	// The rename onto a non-empty directory fails after the bytes were staged.
	blocked := filepath.Join(dir, "0002.req")
	require.NoError(t, os.Mkdir(blocked, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "x"), []byte("x"), 0o600))
	require.Error(t, writeFileAtomic(blocked, []byte(strings.Repeat("A", 1<<20)), mirrorFileMode))

	info, err := os.Stat(blocked)
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "a failed write leaves the destination as it was")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "staging file left behind: %s", e.Name())
	}
}

// A saturated writer: the buffer is full and nobody drains it, so each further
// enqueue waits the timeout, then is dropped and counted.
func TestMirrorDropCounterUnderSaturation(t *testing.T) {
	m, err := newMirror(t.TempDir(), false, 1, 10*time.Millisecond)
	require.NoError(t, err)

	m.OnRecord(sampleRecord("fills-buffer"))
	assert.Equal(t, int64(0), m.Dropped())

	start := time.Now()
	m.OnRecord(sampleRecord("dropped-1"))
	m.OnRecord(sampleRecord("dropped-2"))
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond, "each enqueue waits the timeout first")
	assert.Equal(t, int64(2), m.Dropped())

	// Starting the writer drains the buffer; the next enqueue lands.
	m.start()
	m.OnRecord(sampleRecord("lands"))
	m.Close()
	assert.Equal(t, int64(2), m.Dropped())
}

// A blocked enqueue gets through when the writer frees a slot within the
// timeout: a burst is absorbed rather than dropped.
func TestMirrorEnqueueWaitsForRoom(t *testing.T) {
	m, err := newMirror(t.TempDir(), false, 1, 2*time.Second)
	require.NoError(t, err)
	m.OnRecord(sampleRecord("fills-buffer"))
	go func() {
		time.Sleep(20 * time.Millisecond)
		m.start()
	}()
	m.OnRecord(sampleRecord("waits"))
	m.Close()
	assert.Equal(t, int64(0), m.Dropped())
}

// A torn trailing index line (crash mid-append) is cut on resume, and an index
// id ahead of the files still advances the counter.
func TestMirrorResumeReconcilesIndex(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMirror(dir, false)
	require.NoError(t, err)
	m.OnRecord(sampleRecord("rec-1"))
	m.Close()

	idx := filepath.Join(dir, "traffic", "index.jsonl")
	f, err := os.OpenFile(idx, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"id":"0005","host":"api.example","path":"api.example/0005"}` + "\n" + `{"id":"0006","ho`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	m2, err := NewMirror(dir, false)
	require.NoError(t, err)
	m2.OnRecord(sampleRecord("rec-2"))
	m2.Close()

	assert.FileExists(t, filepath.Join(dir, "traffic", "api.example", "0006.req"),
		"numbering continues after the highest id the index names")
	lines := readJSONLines(t, idx) // fails on any line that is not whole JSON
	require.Len(t, lines, 3, "0001, 0005, then the new 0006; the torn line is gone")
	assert.Equal(t, "0006", lines[2]["id"])
	assert.Equal(t, "GET", lines[2]["method"], "the new entry, not the torn one")
}
