package scratch

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mkdirAged creates a scratch-shaped directory and backdates its mtime. A
// LevelDB store is a directory with files in it, so removal has to take the
// whole tree rather than just an empty dir.
func mkdirAged(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.Mkdir(path, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, "CURRENT"), []byte("MANIFEST-000000\n"), 0o644))
	backdate(t, path, age)
	return path
}

func writeAged(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))
	backdate(t, path, age)
	return path
}

func backdate(t *testing.T, path string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, when, when))
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }

// Everything allocated here must land under this process's own directory. That
// containment is what makes Release total and what keeps the temp-directory
// scans hmap and nuclei run at startup off a shared directory that had grown to
// six figures of entries.
func TestAllocationsLandUnderTheProcessDirectory(t *testing.T) {
	require.NoError(t, Acquire())
	dir, err := processDir()
	require.NoError(t, err)
	require.NotEmpty(t, dir)

	root := Root()
	assert.Equal(t, root, filepath.Dir(dir), "the process directory lives directly under the root")
	assert.Equal(t, filepath.Join(os.TempDir(), rootName), root)

	sub, err := MkdirTemp("diskset-*")
	require.NoError(t, err)
	assert.Equal(t, dir, filepath.Dir(sub))

	f, err := CreateTemp("stateless-*.sqlite")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	assert.Equal(t, dir, filepath.Dir(f.Name()))

	// Release is the backstop: neither of the two above was removed by its
	// owner, and both must still be gone.
	assert.True(t, Release())
	assert.NoDirExists(t, dir)
	assert.NoFileExists(t, f.Name())

	// An extra Release must not report work it did not do.
	assert.False(t, Release())
}

// In server mode two scans share the directory, so the first to finish must not
// take the second's scratch with it.
func TestReleaseIsRefcounted(t *testing.T) {
	require.NoError(t, Acquire())
	require.NoError(t, Acquire())

	dir, err := processDir()
	require.NoError(t, err)
	sub, err := MkdirTemp("diskset-*")
	require.NoError(t, err)

	assert.False(t, Release(), "the first holder leaving must not remove anything")
	assert.DirExists(t, sub, "a scan still running must keep its scratch")

	assert.True(t, Release(), "the last holder leaving removes it")
	assert.NoDirExists(t, dir)
}

// After the last holder leaves, a later scan in the same process must get a
// fresh directory rather than silently falling back to the system temp dir.
func TestAcquireAfterReleaseStartsFresh(t *testing.T) {
	require.NoError(t, Acquire())
	first, err := processDir()
	require.NoError(t, err)
	require.True(t, Release())

	require.NoError(t, Acquire())
	t.Cleanup(func() { Release() })
	second, err := processDir()
	require.NoError(t, err)

	assert.NotEmpty(t, second)
	assert.NotEqual(t, first, second, "a re-acquire must not reuse the removed directory")
	assert.DirExists(t, second)
}

// pids are recycled, so a stale directory from a dead process with the same pid
// must not be adopted by a live one instead of being collected.
func TestProcessDirectoryNameIsNotJustThePID(t *testing.T) {
	require.NoError(t, Acquire())
	t.Cleanup(func() { Release() })
	dir, err := processDir()
	require.NoError(t, err)

	base := filepath.Base(dir)
	assert.True(t, strings.HasPrefix(base, "p"+strconv.Itoa(os.Getpid())+"-"),
		"expected a pid-prefixed name, got %q", base)
	assert.Greater(t, len(base), len("p"+strconv.Itoa(os.Getpid())+"-"),
		"the pid must be qualified by a random suffix")
}

// The leak came from runs killed before their deferred cleanup ran, so the
// sweep is the only thing that ever removes them.
func TestSweepDirRemovesAbandonedProcessDirectories(t *testing.T) {
	dir := t.TempDir()
	stale := mkdirAged(t, dir, "p4242-deadbeef", 48*time.Hour)

	removed, err := sweepDir(dir, DefaultMaxAge, farFuture(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	assert.NoDirExists(t, stale)
}

// mtime doubles as the liveness check: scratch belonging to a running scan is
// being written to, so it must survive.
func TestSweepDirKeepsYoungScratch(t *testing.T) {
	dir := t.TempDir()
	live := mkdirAged(t, dir, "p4242-cafe0000", time.Minute)

	removed, err := sweepDir(dir, DefaultMaxAge, farFuture(), nil)
	require.NoError(t, err)
	assert.Zero(t, removed)
	assert.DirExists(t, live)
}

// Upgrading must drain what older versions left loose in the temp directory,
// which is where the 71,614 diskset directories and 108 GB actually are.
func TestSweepDirCollectsLegacyNames(t *testing.T) {
	dir := t.TempDir()

	legacy := []string{
		mkdirAged(t, dir, "vigolium-diskset-123456", 48*time.Hour),
		mkdirAged(t, dir, "deparos-dedup-987654", 48*time.Hour),
		mkdirAged(t, dir, "reqcache-42", 48*time.Hour),
		mkdirAged(t, dir, "jstangle-job-7", 48*time.Hour),
		writeAged(t, dir, "vigolium-stateless-42.sqlite", 48*time.Hour),
		writeAged(t, dir, "sitemap-9.db", 48*time.Hour),
	}

	removed, err := sweepDir(dir, DefaultMaxAge, farFuture(), LegacyPrefixes)
	require.NoError(t, err)
	assert.Equal(t, len(legacy), removed)
	for _, path := range legacy {
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr), "expected %s to be collected", filepath.Base(path))
	}
}

// The temp directory is shared with every other program on the machine, so the
// legacy pass may only touch names vigolium itself allocated, however old.
func TestSweepDirIgnoresForeignEntries(t *testing.T) {
	dir := t.TempDir()

	foreign := []string{
		mkdirAged(t, dir, "com.apple.launchd.abc", 90*24*time.Hour),
		mkdirAged(t, dir, "nuclei-templates", 90*24*time.Hour),
		writeAged(t, dir, "openssl.cnf", 90*24*time.Hour),
		// Substring, not prefix: another tool's directory that merely mentions
		// ours is still not ours to delete.
		mkdirAged(t, dir, "backup-of-vigolium-diskset-1", 90*24*time.Hour),
	}

	removed, err := sweepDir(dir, DefaultMaxAge, farFuture(), LegacyPrefixes)
	require.NoError(t, err)
	assert.Zero(t, removed)
	for _, path := range foreign {
		_, statErr := os.Stat(path)
		assert.NoError(t, statErr, "%s belongs to another program", filepath.Base(path))
	}
}

// A backlog built up over months must not hold up a scan's teardown, so the
// pass stops at its deadline and leaves the rest for the next run.
func TestSweepDirHonoursTheDeadline(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 256; i++ {
		writeAged(t, dir, "vigolium-stateless-"+strconv.Itoa(i)+".sqlite", 48*time.Hour)
	}

	past := time.Now().Add(-time.Second)
	removed, err := sweepDir(dir, DefaultMaxAge, past, LegacyPrefixes)
	require.NoError(t, err)
	assert.Zero(t, removed, "an already-expired budget must remove nothing")

	// With a real budget the same directory drains.
	removed, err = sweepDir(dir, DefaultMaxAge, farFuture(), LegacyPrefixes)
	require.NoError(t, err)
	assert.Equal(t, 256, removed)
}

// Collecting the directory this very process is writing into would take a live
// scan's scratch with it, so it is excluded whatever the clock says.
func TestSweepDirNeverCollectsThisProcessDirectory(t *testing.T) {
	dir := t.TempDir()
	own := mkdirAged(t, dir, "p9999-abcd1234", 90*24*time.Hour)

	saved := dirPath
	dirPath = own
	t.Cleanup(func() { dirPath = saved })

	removed, err := sweepDir(dir, DefaultMaxAge, farFuture(), nil)
	require.NoError(t, err)
	assert.Zero(t, removed)
	assert.DirExists(t, own, "this process's own scratch must never be swept")
}

// hmap expires stale temp databases by removing any directory whose name
// contains the running executable's name, and nuclei still turns that sweep on
// through its own fastdialer. A root named for the program could be handed to
// someone else's RemoveAll while a scan was using it.
func TestRootNameAvoidsTheHmapSweepMatch(t *testing.T) {
	assert.NotContains(t, strings.ToLower(rootName), "vigolium",
		"the scratch root must not match hmap's executable-name sweep")
}

// go-rod only removes a browser profile through launcher.Cleanup(), which the
// spidering browser never called, so every launch stranded 8-30 MB. That was by
// a wide margin the largest thing vigolium ever left behind - 3,384 profiles and
// 104 GB on one workstation - so the backlog has to be collectable too.
func TestSweepDirCollectsRodProfiles(t *testing.T) {
	profiles := t.TempDir()

	stale := mkdirAged(t, profiles, "b128b59b75a9b1e9", 48*time.Hour)
	live := mkdirAged(t, profiles, "15c1d2b64c66892a", time.Minute)

	// rod owns this directory outright, so no name filter applies: a profile is
	// named by an opaque hash and could not be matched by prefix anyway.
	removed, err := sweepDir(profiles, DefaultMaxAge, farFuture(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	assert.NoDirExists(t, stale)
	assert.DirExists(t, live, "a browser still crawling must keep its profile")
}

// A missing rod cache is the normal case on a machine that has never spidered,
// and must not read as an error.
func TestSweepDirOnMissingDirectory(t *testing.T) {
	removed, err := sweepDir(filepath.Join(t.TempDir(), "absent"), DefaultMaxAge, farFuture(), nil)
	assert.Zero(t, removed)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// hmap names its temp databases after the running executable plus the random
// digits MkdirTemp appends. vigolium no longer enables the dialer history that
// creates them, but nuclei still does and every older release left one per run.
func TestIsHmapTempDir(t *testing.T) {
	for _, name := range []string{"vigolium1976284940", "vigolium0", "vigolium1003944680"} {
		assert.True(t, isHmapTempDir(name), name)
	}
	// The temp directory is somewhere people park files of their own, so a bare
	// "vigolium" prefix is too wide: only the exact digits pattern is ours.
	for _, name := range []string{
		"vigolium", "vigolium-report.html", "vigolium-2026-notes",
		"vigolium_1234", "my-vigolium1234", "", "nuclei123",
	} {
		assert.False(t, isHmapTempDir(name), name)
	}
}
