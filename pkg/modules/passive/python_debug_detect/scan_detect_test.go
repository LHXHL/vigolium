package python_debug_detect

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

// TestScanPerRequest_WerkzeugDebugger drives a response exposing the Werkzeug
// Debugger and expects a Critical finding from this module.
func TestScanPerRequest_WerkzeugDebugger(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", "<title>Werkzeug Debugger</title>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Werkzeug Debugger")
}

// TestScanPerRequest_Traceback drives a Python traceback and expects a finding.
func TestScanPerRequest_Traceback(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", "Traceback (most recent call last):\n  File \"/app/main.py\", line 10")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
}

// TestScanPerRequest_Benign drives an ordinary HTML page with no debug markers
// and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", "<html><body>Welcome</body></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_BarePathMarkerNoContext ensures a path-disclosure substring
// that appears without any real Python error/debug surface (e.g. a benign JSON
// API echoing an installed-package path, or docs) is dropped, not reported.
func TestScanPerRequest_BarePathMarkerNoContext(t *testing.T) {
	t.Parallel()
	m := New()
	// A normal JSON body that merely mentions a site-packages path and a quoted
	// file path — no traceback, no Werkzeug, no Django debug page.
	ctx := modtest.HTTPCtx("/", "text/html", `{"docs":"install to /usr/lib/python3/site-packages/","example":"File \"/etc/app.cfg\""}`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "bare path markers without a Python error context must not fire")
}

// TestScanPerRequest_PathMarkerWithTraceback ensures the path-disclosure markers
// still fire when corroborated by a real Python traceback in the same response.
func TestScanPerRequest_PathMarkerWithTraceback(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", "Traceback (most recent call last):\n  File \"/usr/lib/python3/site-packages/flask/app.py\", line 1")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Info.Name)
	}
	assert.Contains(t, names, "Python Debug: Python Dependency Path Disclosure")
}
