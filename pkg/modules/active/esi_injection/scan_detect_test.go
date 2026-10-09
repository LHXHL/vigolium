package esi_injection

import (
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// fakeOAST records what the module planted.
type fakeOAST struct {
	mu       sync.Mutex
	types    []string
	recorded []string
}

func (f *fakeOAST) GenerateURL(_, _, injectionType, _, _ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.types = append(f.types, injectionType)
	return "esi.oast.test"
}

func (f *fakeOAST) RecordPayload(_, payload string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, payload)
}

func (f *fakeOAST) Enabled() bool { return true }

func (f *fakeOAST) payloads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.recorded...)
}

var (
	esiTag = regexp.MustCompile(`<esi:[^>]*/>`)
	anyTag = regexp.MustCompile(`<[^>]*>`)
)

func page(body string) string { return "<html><body>search: " + body + "</body></html>" }

// htmlHandler serves render(q) as an HTML page and counts requests.
func htmlHandler(hits *int64, render func(q string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(render(r.URL.Query().Get("q"))))
	}
}

func scanQ(t *testing.T, h http.Handler, oast modkit.OASTProvider) []*output.ResultEvent {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rr := modtest.Request(t, srv.URL+"/search?q=hello")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)
	return res
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, "esi", m.VulnClass())
	assert.True(t, m.ConfirmsByBodyDifferential())
	assert.Contains(t, m.Tags(), "moderate")
}

// TestESIProcessor_Detected: an edge that removes esi:* elements and leaves
// every other tag alone makes the probe's tags adjacent; the control survives.
func TestESIProcessor_Detected(t *testing.T) {
	t.Parallel()
	var hits int64
	oast := &fakeOAST{}
	res := scanQ(t, htmlHandler(&hits, func(q string) string {
		return page(esiTag.ReplaceAllString(q, ""))
	}), oast)
	require.Len(t, res, 1)
	f := res[0]
	assert.Equal(t, "q", f.FuzzingParameter)
	assert.Contains(t, f.Request, "esi")
	assert.Contains(t, f.Response, "search: vgo")
	assert.NotEmpty(t, f.AdditionalEvidence)
	assert.Equal(t, int64(2), atomic.LoadInt64(&hits), "probe + control")
	assert.Empty(t, oast.payloads(), "a confirmed in-band finding needs no include leg")
}

// TestTagStrippingWAF_NoFinding: a sanitizer that strips every tag also makes
// the probe's tags adjacent, but the non-ESI control is stripped too.
func TestTagStrippingWAF_NoFinding(t *testing.T) {
	t.Parallel()
	var hits int64
	res := scanQ(t, htmlHandler(&hits, func(q string) string {
		return page(anyTag.ReplaceAllString(q, ""))
	}), nil)
	assert.Empty(t, res)
}

// TestEscapedReflection_FiresInclude: HTML-escaped reflection is not
// processed, but the input reached a rendered page, so the OAST include leg is
// planted.
func TestEscapedReflection_FiresInclude(t *testing.T) {
	t.Parallel()
	var hits int64
	oast := &fakeOAST{}
	res := scanQ(t, htmlHandler(&hits, func(q string) string {
		return page(html.EscapeString(q))
	}), oast)
	assert.Empty(t, res)

	got := oast.payloads()
	require.Len(t, got, 1)
	assert.Equal(t, `<esi:include src="http://esi.oast.test/"/>`, got[0])
	oast.mu.Lock()
	defer oast.mu.Unlock()
	for _, typ := range oast.types {
		assert.NotContains(t, strings.ToLower(typ), "header")
	}
}

// TestRawReflection_NoFinding: verbatim reflection keeps the element between
// the tags.
func TestRawReflection_NoFinding(t *testing.T) {
	t.Parallel()
	var hits int64
	res := scanQ(t, htmlHandler(&hits, page), nil)
	assert.Empty(t, res)
}

// TestBlockPage_NoFinding: a WAF block page echoing a tag-stripped URL is the
// edge talking, not the application.
func TestBlockPage_NoFinding(t *testing.T) {
	t.Parallel()
	oast := &fakeOAST{}
	res := scanQ(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(page("Access Denied: " + esiTag.ReplaceAllString(r.URL.Query().Get("q"), ""))))
	}), oast)
	assert.Empty(t, res)
	assert.Empty(t, oast.payloads(), "a blocked response is not a reached render")
}

// TestNoReflection_NoInclude: input that never reaches the response gets no
// include leg.
func TestNoReflection_NoInclude(t *testing.T) {
	t.Parallel()
	var hits int64
	oast := &fakeOAST{}
	res := scanQ(t, htmlHandler(&hits, func(string) string { return page("nothing") }), oast)
	assert.Empty(t, res)
	assert.Empty(t, oast.payloads())
	assert.Equal(t, int64(1), atomic.LoadInt64(&hits))
}

// TestBinaryBaseline_Skipped: a binary baseline response is never probed.
func TestBinaryBaseline_Skipped(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(htmlHandler(&hits, page))
	t.Cleanup(srv.Close)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/img?q=hello"), "image/png", "\x89PNG")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Equal(t, int64(0), atomic.LoadInt64(&hits))
}
