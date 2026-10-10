package nextjs_config_audit

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

// TestScanPerRequest_ProductionSourceMaps drives a next.config blob enabling
// productionBrowserSourceMaps, a clear misconfiguration pattern.
func TestScanPerRequest_ProductionSourceMaps(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { productionBrowserSourceMaps: true }`
	ctx := modtest.HTTPCtxHeaders("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Production Source Maps")
}

// TestScanPerRequest_WildcardImageHostname drives the SSRF-prone wildcard
// remotePatterns hostname.
func TestScanPerRequest_WildcardImageHostname(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { images: { remotePatterns: [{ hostname: "**" }] } }`
	ctx := modtest.HTTPCtxHeaders("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	found := false
	for _, r := range results {
		if r.Info.Name == "Next.js Config: Wildcard Image Hostname" {
			found = true
		}
	}
	assert.True(t, found, "expected wildcard hostname finding")
}

// TestScanPerRequest_Benign verifies a clean config produces no finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `module.exports = { reactStrictMode: true }`
	ctx := modtest.HTTPCtxHeaders("/next.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
