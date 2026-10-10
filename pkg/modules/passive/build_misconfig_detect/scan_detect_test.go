package build_misconfig_detect

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

// TestCanProcess_JS verifies a JavaScript content type is accepted.
func TestCanProcess_JS(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/app.js", "application/javascript", "console.log(1)")
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_SourceMaps drives a JS config exposing production source
// maps, which should be flagged as a build misconfiguration.
func TestScanPerRequest_SourceMaps(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { productionBrowserSourceMaps: true, reactStrictMode: false }`
	ctx := modtest.HTTPCtx("/next.config.js", "application/javascript", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Build Misconfiguration")
}

// TestScanPerRequest_DevStart drives a package.json with a dev-mode start
// script, which should be flagged.
func TestScanPerRequest_DevStart(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"scripts": {"start": "next dev", "build": "next build"}}`
	ctx := modtest.HTTPCtx("/package.json", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NonConfigBundle is a regression: a regular app bundle (not
// a config file by URL or anchor) that embeds a config-shaped string must NOT be
// flagged — attribution is required before the config regexes run.
func TestScanPerRequest_NonConfigBundle(t *testing.T) {
	t.Parallel()
	m := New()
	body := `var opts={sourcemap:true,images:{hostname:"**"}};render(opts);`
	ctx := modtest.HTTPCtx("/assets/index-uYP.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Clean verifies a benign JS config produces no findings.
func TestScanPerRequest_Clean(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { reactStrictMode: true, poweredByHeader: false }`
	ctx := modtest.HTTPCtx("/next.config.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
