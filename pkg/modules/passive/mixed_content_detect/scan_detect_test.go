package mixed_content_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_MixedContent drives an HTTPS HTML page referencing an
// http:// script and stylesheet, the core mixed-content trigger.
func TestScanPerRequest_MixedContent(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head>` +
		`<script src="http://cdn.example.com/app.js"></script>` +
		`<link href="http://cdn.example.com/style.css" rel="stylesheet">` +
		`</head></html>`
	ctx := modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].ExtractedResults)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Contains(t, results[0].Info.Name, "Blockable")
}

func TestScanPerRequest_OrdinaryHTTPNavigationIsNotMixedContent(t *testing.T) {
	t.Parallel()
	body := `<html><body>` +
		`<a href="http://example.net/page">navigate</a>` +
		`<link rel="canonical" href="http://example.com/canonical">` +
		`</body></html>`
	results, err := New().ScanPerRequest(modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_UpgradeableMediaIsObservation(t *testing.T) {
	t.Parallel()
	body := `<img src="http://cdn.example.net/image.png"><video poster="http://cdn.example.net/poster.jpg"></video>`
	results, err := New().ScanPerRequest(modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Contains(t, results[0].Info.Name, "Upgradeable")
}

func TestScanPerRequest_HTTPFormIsSeparateDowngrade(t *testing.T) {
	t.Parallel()
	body := `<form action="http://accounts.example.net/login" method="post"><input type="password" name="password"></form>`
	results, err := New().ScanPerRequest(modtest.HTTPCtxHeaders("/login", "Content-Type: text/html\r\n", body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, "HTTPS Form Submits to HTTP", results[0].Info.Name)
}

func TestScanPerRequest_LoopbackHTTPIsPotentiallyTrustworthy(t *testing.T) {
	t.Parallel()
	body := `<script src="http://localhost:3000/dev.js"></script><img src="http://127.0.0.1/pixel.png">`
	results, err := New().ScanPerRequest(modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_MarkupInsideScriptIsIgnored(t *testing.T) {
	t.Parallel()
	body := `<script>const example = '<a href="http://x.example/">x</a>';</script>`
	results, err := New().ScanPerRequest(modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_AllHTTPS verifies a page referencing only https:// assets
// produces no finding.
func TestScanPerRequest_AllHTTPS(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><script src="https://cdn.example.com/app.js"></script></head></html>`
	ctx := modtest.HTTPCtxHeaders("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTML verifies non-HTML content types are skipped.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtxHeaders("/data", "Content-Type: application/json\r\n", `{"u":"http://x.com/a.js"}`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
