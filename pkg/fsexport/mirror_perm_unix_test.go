//go:build unix

package fsexport

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// withUmask clears the umask for the test so the asserted modes are the ones
// the mirror asked for, not the developer's umask.
func withUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

// The mirror holds raw traffic, so every file is 0600 and every directory 0700
// regardless of a permissive umask.
func TestMirrorOwnerOnlyPermissions(t *testing.T) {
	withUmask(t)
	dir := t.TempDir()
	m, err := NewMirror(dir, false)
	require.NoError(t, err)
	m.OnRecord(sampleRecord("rec-1"))
	m.OnFinding(&database.Finding{
		HTTPRecordUUIDs: []string{"rec-1"}, ModuleID: "m", Severity: "low",
		Hostname: "api.example", URL: "https://api.example/users",
	})
	m.Close()

	var files, dirs int
	require.NoError(t, filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if path == dir {
			return nil
		}
		if info.IsDir() {
			dirs++
			assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "dir %s", path)
		} else {
			files++
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "file %s", path)
		}
		return nil
	}))
	assert.GreaterOrEqual(t, files, 5, ".req, .resp.headers, .resp.body, .md, two indexes")
	assert.GreaterOrEqual(t, dirs, 4)
}
