package ssr_hydration_xss

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_ScriptBreakout drives a __NEXT_DATA__ hydration block containing
// an unescaped </script> breakout — the primary XSS vector.
func TestScanPerRequest_ScriptBreakout(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>` +
		`<script id="__NEXT_DATA__" type="application/json">{"q":"x</script><img src=x onerror=alert(1)>y"}</script>` +
		`</body></html>`
	ctx := modtest.HTTPCtx("/page", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, "Hydration Serialization Truncated by Script Boundary", results[0].Info.Name)
}

// A raw angle bracket that does not form a script end tag remains in script raw
// text and cannot by itself escape into HTML.
func TestScanPerRequest_RawAngleWithoutEndTagIsSafe(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__PRELOADED_STATE__={"name":"hello <world tag"}</script></html>`
	ctx := modtest.HTTPCtx("/dashboard", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_SafeHydration verifies that a properly escaped hydration block
// (with < encoding) produces no findings.
func TestScanPerRequest_SafeHydration(t *testing.T) {
	t.Parallel()
	m := New()
	body := "<html><script>window.__PRELOADED_STATE__={\"name\":\"hello \\u003cworld\\u003e\"}</script></html>"
	ctx := modtest.HTTPCtx("/dashboard", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoHydration verifies that an HTML page without any hydration
// script blocks produces no findings.
func TestScanPerRequest_NoHydration(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", "<html><body><p>Hello World</p></body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_ValidHydrationFollowedByInlineScriptIsNotBreakout(t *testing.T) {
	t.Parallel()
	body := `<script id="__NEXT_DATA__" type="application/json">{"name":"hello <b>world</b>"}</script>` +
		`<script>window.appStarted=true</script>`
	results, err := New().ScanPerRequest(modtest.HTTPCtx("/", "text/html", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_TruncationWithoutExecutableTailIsNotXSS(t *testing.T) {
	t.Parallel()
	body := `<script>window.__PRELOADED_STATE__={"name":"truncated</script><p>ordinary content</p>`
	results, err := New().ScanPerRequest(modtest.HTTPCtx("/", "text/html", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_ReflectedBreakoutRaisesConfidence(t *testing.T) {
	t.Parallel()
	payload := `</script><img src=x onerror=alert(1)>`
	body := `<script>window.__PRELOADED_STATE__={"q":"` + payload + `"}</script>`
	ctx := modtest.HTTPCtx("/search?q=%3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E", "text/html", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.Firm, results[0].Info.Confidence)
	assert.Equal(t, "q", results[0].Metadata["reflected_param"])
}
