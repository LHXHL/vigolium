package cli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
)

// TestRenderServerReport covers REST `output_formats:["html"]`: the server's
// injected renderer produces the file through the same generator `scan
// --format html` uses, scoped to the scan, and refuses formats it has no
// renderer for.
func TestRenderServerReport(t *testing.T) {
	db := newExportTestDB(t)
	const proj = "00000000-0000-0000-0000-0000000000aa"
	seedFindingAndRecord(t, db, proj, "srv")

	out := filepath.Join(t.TempDir(), "scan-1", "output.html") // dir does not exist yet
	require.NoError(t, renderServerReport(context.Background(), db, "html", out, proj, ""))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), "<html")

	assert.Error(t, renderServerReport(context.Background(), db, "fs", out, proj, ""),
		"a format with no renderer must error, never silently succeed")
	assert.Contains(t, serverReportFormats(), "html")
	assert.NotContains(t, serverReportFormats(), "jsonl", "jsonl is the runner's live stream, not a report")
}

// TestServerHelpNamesRealAPIKey guards the help text: it must name the config
// key the server actually reads (server.auth_api_key), not a key that doesn't
// exist.
func TestServerHelpNamesRealAPIKey(t *testing.T) {
	assert.Contains(t, serverCmd.Long, "server.auth_api_key")
	assert.NotContains(t, serverCmd.Long, "server.api_key")

	f, ok := reflect.TypeOf(config.ServerConfig{}).FieldByName("AuthAPIKey")
	require.True(t, ok)
	assert.Equal(t, "auth_api_key", f.Tag.Get("yaml"))
}

func TestProxyCATrustHint(t *testing.T) {
	assert.Contains(t, proxyCATrustHint("/tmp/ca.pem", 8899), "http://127.0.0.1:8899")
	noPort := proxyCATrustHint("/tmp/ca.pem", 0)
	assert.NotContains(t, noPort, "9090", "must not invent a port")
	assert.True(t, strings.Contains(noPort, "--ingest-proxy-port"))
}
