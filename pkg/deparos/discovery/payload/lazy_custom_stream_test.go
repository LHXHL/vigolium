package payload

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
)

func writeList(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func drain(t *testing.T, p Provider) []string {
	t.Helper()
	var out []string
	for {
		v, err := p.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		require.NoError(t, err)
		out = append(out, string(v))
	}
}

// Words repeated within one file and across files are emitted once, in
// first-seen order, through the on-disk set the engine passes.
func TestStreamingFilesProvider_DedupAcrossFilesOnDisk(t *testing.T) {
	dir := t.TempDir()
	a := writeList(t, dir, "a.txt", "admin\n  api \n\nadmin\nlogin\n")
	b := writeList(t, dir, "b.txt", "api\nbackup\nlogin\nconfig\r\n")

	ds, err := dedup.NewDiskSet(&dedup.Config{BasePath: t.TempDir(), Namespace: "fuzz-words", Cleanup: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ds.Close() })

	p, err := NewStreamingFilesProvider("fuzz", []string{a, b}, ds)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "api", "login", "backup", "config"}, drain(t, p))

	// Exhausted stays exhausted.
	_, err = p.Next(context.Background())
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, p.Close())
}

func TestStreamingFilesProvider_NilSeenUsesMemorySet(t *testing.T) {
	dir := t.TempDir()
	a := writeList(t, dir, "a.txt", "x\ny\nx\n")
	b := writeList(t, dir, "b.txt", "y\nz\n")
	p, err := NewStreamingFilesProvider("fuzz", []string{a, b}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"x", "y", "z"}, drain(t, p))
}

func TestStreamingFilesProvider_ReadsGzip(t *testing.T) {
	dir := t.TempDir()
	gzPath := filepath.Join(dir, "words.txt.gz")
	f, err := os.Create(gzPath)
	require.NoError(t, err)
	zw := gzip.NewWriter(f)
	_, _ = zw.Write([]byte("one\ntwo\n"))
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
	plain := writeList(t, dir, "plain.txt", "two\nthree\n")

	p, err := NewStreamingFilesProvider("fuzz", []string{gzPath, plain}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"one", "two", "three"}, drain(t, p))
}

func TestStreamingFilesProvider_RejectsMissingOrDirectory(t *testing.T) {
	dir := t.TempDir()
	ok := writeList(t, dir, "ok.txt", "a\n")

	_, err := NewStreamingFilesProvider("fuzz", []string{ok, filepath.Join(dir, "missing.txt")}, nil)
	assert.Error(t, err)
	_, err = NewStreamingFilesProvider("fuzz", []string{dir}, nil)
	assert.Error(t, err)
	_, err = NewStreamingFilesProvider("fuzz", nil, nil)
	assert.Error(t, err)
}

// A file removed after validation is reported once and skipped; streaming
// carries on with the remaining files.
func TestStreamingFilesProvider_SkipsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	gone := writeList(t, dir, "gone.txt", "lost\n")
	keep := writeList(t, dir, "keep.txt", "kept\n")
	p, err := NewStreamingFilesProvider("fuzz", []string{gone, keep}, nil)
	require.NoError(t, err)
	require.NoError(t, os.Remove(gone))

	_, err = p.Next(context.Background())
	require.Error(t, err)
	assert.Equal(t, []string{"kept"}, drain(t, p))
}

func TestStreamingFilesProvider_HashDependsOnOrderedPaths(t *testing.T) {
	dir := t.TempDir()
	a := writeList(t, dir, "a.txt", "a\n")
	b := writeList(t, dir, "b.txt", "b\n")
	p1, _ := NewStreamingFilesProvider("fuzz", []string{a, b}, nil)
	p2, _ := NewStreamingFilesProvider("fuzz", []string{a, b}, nil)
	p3, _ := NewStreamingFilesProvider("fuzz", []string{b, a}, nil)
	assert.Equal(t, p1.HashContent(), p2.HashContent())
	assert.NotEqual(t, p1.HashContent(), p3.HashContent())
}
