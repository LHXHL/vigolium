package php_generic_fingerprint

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

// TestScanPerRequest_PoweredByPHP drives the X-Powered-By: PHP/x header, which
// also surfaces the version.
func TestScanPerRequest_PoweredByPHP(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nX-Powered-By: PHP/8.2.1\r\n"
	ctx := modtest.HTTPCtxHeaders("/", headers, `<html></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "PHP Application Detected", results[0].Info.Name)
	assert.Equal(t, "8.2.1", results[0].Metadata["version"])
}

// TestScanPerRequest_PHPSessIDCookie drives the PHPSESSID Set-Cookie signal.
func TestScanPerRequest_PHPSessIDCookie(t *testing.T) {
	t.Parallel()
	m := New()
	headers := "Content-Type: text/html\r\nSet-Cookie: PHPSESSID=abc123; path=/\r\n"
	ctx := modtest.HTTPCtxHeaders("/", headers, `<html></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_DotPHPAlone verifies a bare .php path with no header or
// cookie signal is too weak and not flagged.
func TestScanPerRequest_DotPHPAlone(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtxHeaders("/index.php", "Content-Type: text/html\r\n", `<html></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a plain response yields no fingerprint.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\nServer: nginx\r\n", `<html></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
