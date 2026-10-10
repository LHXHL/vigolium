package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func parseDiscoveryWordlistFlags(t *testing.T, args ...string) []string {
	t.Helper()
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerNativeScanFlags(fs, false)
	require.NoError(t, fs.Parse(args))
	return scanOpts.FuzzWordlistPaths
}

func touchWordlist(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte("admin\n"), 0o644))
	return p
}

func requireUsageError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var ue clicommon.UsageError
	assert.True(t, errors.As(err, &ue), "want a usage error (exit 2), got %T: %v", err, err)
}

func TestDiscoveryWordlistFlag_Repeatable(t *testing.T) {
	dir := t.TempDir()
	a := touchWordlist(t, dir, "a.txt")
	b := touchWordlist(t, dir, "b.txt")

	got := parseDiscoveryWordlistFlags(t, "--discovery-wordlist", a, "--discovery-wordlist", b)
	assert.Equal(t, []string{a, b}, got, "each repeat is kept, in order")

	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerNativeScanFlags(fs, false)
	assert.Equal(t, "stringArray", fs.Lookup("discovery-wordlist").Value.Type(),
		"a StringArray does not split on commas, so a path with a comma survives parsing")

	norm, err := normalizeDiscoveryWordlists(got)
	require.NoError(t, err)
	assert.Equal(t, []string{a, b}, norm)

	// Duplicates collapse.
	norm, err = normalizeDiscoveryWordlists([]string{a, b, a})
	require.NoError(t, err)
	assert.Equal(t, []string{a, b}, norm)
}

func TestDiscoveryWordlistFlag_CommaJoined(t *testing.T) {
	dir := t.TempDir()
	a := touchWordlist(t, dir, "a.txt")
	b := touchWordlist(t, dir, "b.txt")

	t.Run("split when every part exists", func(t *testing.T) {
		got := parseDiscoveryWordlistFlags(t, "--discovery-wordlist", a+","+b)
		assert.Equal(t, []string{a + "," + b}, got, "parsing keeps the raw value")
		norm, err := normalizeDiscoveryWordlists(got)
		require.NoError(t, err)
		assert.Equal(t, []string{a, b}, norm)
	})

	t.Run("a file whose name has a comma stays one path", func(t *testing.T) {
		comma := touchWordlist(t, dir, "x,y.txt")
		norm, err := normalizeDiscoveryWordlists([]string{comma})
		require.NoError(t, err)
		assert.Equal(t, []string{comma}, norm)
	})

	t.Run("not split when a part is missing", func(t *testing.T) {
		_, err := normalizeDiscoveryWordlists([]string{a + "," + filepath.Join(dir, "nope.txt")})
		requireUsageError(t, err)
	})
}

func TestDiscoveryWordlistFlag_MissingIsUsageError(t *testing.T) {
	dir := t.TempDir()
	a := touchWordlist(t, dir, "a.txt")

	_, err := normalizeDiscoveryWordlists([]string{a, filepath.Join(dir, "missing.txt")})
	requireUsageError(t, err)
	assert.Contains(t, err.Error(), "missing.txt")

	_, err = normalizeDiscoveryWordlists([]string{dir})
	requireUsageError(t, err)

	_, err = normalizeDiscoveryWordlists([]string{"  "})
	requireUsageError(t, err)

	norm, err := normalizeDiscoveryWordlists(nil)
	require.NoError(t, err)
	assert.Nil(t, norm)
}
