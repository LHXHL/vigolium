package drupal_api_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_JSONAPI drives a JSON:API content type plus body structure,
// the primary content-based detection signal.
func TestScanPerRequest_JSONAPI(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"jsonapi":{"version":"1.0"},"links":{"self":"/jsonapi/node/article"}}`
	ctx := modtest.HTTPCtx("/jsonapi/node/article", "application/vnd.api+json", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "JSON:API")
}

// TestScanPerRequest_PathOnly verifies a JSON:API-shaped path with no
// content-based signal is not reported (path-only matches are too generic).
func TestScanPerRequest_PathOnly(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/jsonapi/node", "text/html", `<html>not drupal</html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies an ordinary HTML page is not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", `<html><body>hello</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
