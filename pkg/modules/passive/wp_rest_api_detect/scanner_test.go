package wp_rest_api_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func TestScanPerRequest_IndexWithCustomNamespaces(t *testing.T) {
	m := New()
	body := `{
		"name": "Example Site",
		"namespaces": ["wp/v2", "wp-site-health/v1", "oembed/1.0", "contact-form-7/v1", "yoast/v1"]
	}`
	ctx := modtest.HTTPCtx("/wp-json/", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	r := results[0]
	assert.Contains(t, r.Info.Name, "Namespaces")
	assert.Contains(t, r.Info.Description, "contact-form-7/v1")
	assert.Contains(t, r.Info.Description, "yoast/v1")

	customNS, ok := r.Metadata["customNamespaces"].([]string)
	require.True(t, ok)
	assert.Contains(t, customNS, "contact-form-7/v1")
	assert.Contains(t, customNS, "yoast/v1")
}

func TestScanPerRequest_IndexCoreOnly(t *testing.T) {
	m := New()
	body := `{
		"name": "Example Site",
		"namespaces": ["wp/v2", "wp-site-health/v1", "oembed/1.0"]
	}`
	ctx := modtest.HTTPCtx("/wp-json/", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	customNS, ok := r.Metadata["customNamespaces"].([]string)
	require.True(t, ok)
	assert.Empty(t, customNS)
}

func TestScanPerRequest_UserExposure(t *testing.T) {
	m := New()
	body := `[
		{"id": 1, "slug": "admin", "name": "Admin User"},
		{"id": 2, "slug": "editor", "name": "Editor"}
	]`
	ctx := modtest.HTTPCtx("/wp-json/wp/v2/users", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "WordPress Users Exposed via REST API" {
			found = true
			assert.Contains(t, r.Info.Description, "2 user account")
			assert.Contains(t, r.ExtractedResults, "admin (id:1)")
			break
		}
	}
	assert.True(t, found, "expected user exposure finding")
}

func TestScanPerRequest_NonWPJSON(t *testing.T) {
	m := New()
	ctx := modtest.HTTPCtx("/api/v1/data", "application/json", `{"key": "value"}`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NonJSON(t *testing.T) {
	m := New()
	ctx := modtest.HTTPCtx("/wp-json/", "text/html", `<html>Not JSON</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}
