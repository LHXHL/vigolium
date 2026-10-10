package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// --module-id ext-<id> is not checked against the built-in registry (no warning
// from validateModuleSelectionFlags); the runner checks it once the extension
// engine has loaded and fails the scan as a usage error before any request.
func TestScanModuleIDUnknownExtensionExits2(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	ext := filepath.Join(home, "a.js")
	require.NoError(t, os.WriteFile(ext, []byte(`module.exports = {
  id: "a", type: "active", severity: "low",
  scanPerRequest: function(ctx) { return null; }
};`), 0o600))

	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "-j",
		"--db", filepath.Join(home, "f2.sqlite"), "--ext", ext, "--module-id", "ext-nope")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeUsageError), errorCode(t, stdout))
	assert.Contains(t, stdout, "ext-nope")
	assert.Contains(t, stdout, "ext-a", "the error lists the loaded extensions")
	assert.Zero(t, hits.Load(), "an unknown extension ID must fail before any request")
}

func TestValidateModuleSelectionFlagsSkipsExtensionIDs(t *testing.T) {
	setModuleFlags(t, []string{"ext-anything"}, false)
	assert.NoError(t, validateModuleSelectionFlags(false))
}
