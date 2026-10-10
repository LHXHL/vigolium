package joomla_fingerprint

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

// TestScanPerRequest_GeneratorTag drives an HTML body with a Joomla generator
// meta tag plus system asset path and expects a CMS fingerprint finding.
func TestScanPerRequest_GeneratorTag(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<head><meta name="generator" content="Joomla! - Open Source Content Management">
		<script src="/media/system/js/core.js"></script></head>`
	ctx := modtest.HTTPCtx("/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Joomla")
}

// TestScanPerRequest_Joomla4WithExtensions drives a Joomla 4+ body (api path +
// JS API) referencing a component and expects extension enumeration.
func TestScanPerRequest_Joomla4WithExtensions(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>Joomla.getOptions('csrf.token');</script>
		<link href="/components/com_content/style.css">
		<a href="/api/index.php/v1/articles">api</a></html>`
	ctx := modtest.HTTPCtx("/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "4+", results[0].Metadata["generation"])
	exts, ok := results[0].Metadata["extensions"].([]string)
	require.True(t, ok)
	assert.Contains(t, exts, "com_content")
}

// TestScanPerRequest_WeakSignalsOnly is a regression: generic "/administrator/"
// and "/api/index.php" references without any Joomla-specific signal must NOT
// attribute Joomla on their own (they exist on countless non-Joomla sites).
func TestScanPerRequest_WeakSignalsOnly(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><a href="/administrator/login">Admin</a><a href="/api/index.php">API</a></html>`
	ctx := modtest.HTTPCtx("/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NotJoomla drives a benign HTML response with no Joomla
// signals and expects no findings.
func TestScanPerRequest_NotJoomla(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", `<html><body>Just a plain page</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
