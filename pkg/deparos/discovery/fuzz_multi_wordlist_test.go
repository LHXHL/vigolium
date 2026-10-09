package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// Several fuzz wordlists become one FuzzTask that tries each word once, with
// the dedup held in the engine's on-disk set rather than in memory.
func TestCreateFuzzTask_MultipleWordlistsDedupOnDisk(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	require.NoError(t, os.WriteFile(a, []byte("admin\napi\nadmin\n"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("api\nbackup\n"), 0o644))

	cfg := config.NewDefaultConfig()
	cfg.Filenames.Wordlists.FuzzWordlistPaths = []string{a, b}
	cfg.Filenames.Wordlists.FuzzWordlistPath = filepath.Join(dir, "ignored-legacy.txt")
	assert.Equal(t, []string{a, b}, cfg.Filenames.Wordlists.FuzzWordlists(), "the multi-path field wins over the legacy one")

	seen, err := newDiskSet(t.TempDir(), "fuzz-words")
	require.NoError(t, err)
	t.Cleanup(func() { _ = seen.Close() })

	task, err := NewFactory(cfg).CreateFuzzTask("http://example.com/FUZZ", cfg.Filenames.Wordlists.FuzzWordlists(), seen, 0)
	require.NoError(t, err)

	var got []string
	require.NoError(t, task.Expand(context.Background(), func(u string, _ uint16) { got = append(got, u) }))
	assert.Equal(t, []string{
		"http://example.com/admin",
		"http://example.com/api",
		"http://example.com/backup",
	}, got)
}

func TestCreateFuzzTask_MissingWordlistFails(t *testing.T) {
	cfg := config.NewDefaultConfig()
	_, err := NewFactory(cfg).CreateFuzzTask("http://example.com/FUZZ", []string{filepath.Join(t.TempDir(), "nope.txt")}, nil, 0)
	assert.Error(t, err)
}

func TestWordlistConfig_FuzzWordlistsLegacyFallback(t *testing.T) {
	w := config.WordlistConfig{FuzzWordlistPath: "/x/fuzz.txt"}
	assert.Equal(t, []string{"/x/fuzz.txt"}, w.FuzzWordlists())
	assert.True(t, w.HasFuzzWordlist())

	w = config.WordlistConfig{FuzzWordlistPaths: []string{"", ""}}
	assert.False(t, w.HasFuzzWordlist())
}
