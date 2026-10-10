package directory_listing_detect

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

// TestScanPerRequest_ApacheListing drives the Apache directory-listing
// signature (title + h1 "Index of"), the main detection path.
func TestScanPerRequest_ApacheListing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>`
	ctx := modtest.HTTPCtx("/uploads/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Name, "Apache")
}

// TestScanPerRequest_GenericListing drives the generic "Directory listing for"
// path (Python http.server): a listing <title> corroborated by real file-index
// structure (<h1> + <hr>-bracketed <ul> of links).
func TestScanPerRequest_GenericListing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><title>Directory listing for /files/</title></head><body>` +
		`<h1>Directory listing for /files/</h1><hr><ul>` +
		`<li><a href="dump.sql">dump.sql</a></li></ul><hr></body></html>`
	ctx := modtest.HTTPCtx("/files/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoListing verifies an ordinary HTML page is not flagged.
func TestScanPerRequest_NoListing(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := modtest.HTTPCtx("/", "text/html", `<html><body>Welcome home</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_ContentPageTitledDirectoryOfNoFinding guards the generic
// title-only false positive: a real content page merely titled "Directory of X"
// (staff directory, glossary index) has no file-index structure and must not be
// flagged as a directory listing.
func TestScanPerRequest_ContentPageTitledDirectoryOfNoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><title>Directory of Physicians</title></head><body>` +
		`<h1>Find a Doctor</h1><ul><li><a href="/doctor/jane-roe">Jane Roe</a></li>` +
		`<li><a href="/doctor/john-doe">John Doe</a></li></ul></body></html>`
	ctx := modtest.HTTPCtx("/physicians/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, `a content page titled "Directory of X" without listing structure is not an autoindex`)
}

// TestScanPerRequest_AppPageNoFinding guards the CMS/SPA false positive: a
// rendered application page (framework/OpenGraph markers) whose title matches a
// listing phrase must not be flagged.
func TestScanPerRequest_AppPageNoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><meta name="generator" content="Gatsby 5.13.3">` +
		`<meta property="og:title" content="Index of Publications">` +
		`<title>Index of Publications</title></head><body>` +
		`<h1>Index of Publications</h1><hr><ul><li><a href="/pub/1">One</a></li></ul></body></html>`
	ctx := modtest.HTTPCtx("/publications/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a rendered app/CMS page is not an autoindex even with a listing-shaped title")
}
