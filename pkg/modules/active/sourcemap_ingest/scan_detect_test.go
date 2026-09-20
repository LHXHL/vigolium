package sourcemap_ingest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// recordingFeeder captures what the module injects back into the scan.
type recordingFeeder struct {
	mu  sync.Mutex
	fed []string
}

func (f *recordingFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := rr.URL()
	if err != nil {
		return false
	}
	f.fed = append(f.fed, u.String())
	return true
}

func (f *recordingFeeder) urls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.fed...)
}

// mapWithSources builds a v3 map whose originals call the given API routes.
func mapWithSources(t *testing.T, embedContent bool, routes ...string) string {
	t.Helper()
	body := map[string]any{
		"version":  3,
		"sources":  []string{"src/api/client.ts"},
		"mappings": "AAAA",
	}
	if embedContent {
		calls := make([]string, 0, len(routes))
		for _, route := range routes {
			calls = append(calls, "await fetch(\""+route+"\");")
		}
		body["sourcesContent"] = []string{
			"export async function load() {\n  " + strings.Join(calls, "\n  ") + "\n}",
		}
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return string(encoded)
}

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.True(t, m.ScanScopes().Has(modkit.ScanScopeRequest))
	assert.NotEmpty(t, m.Tags())
	assert.False(t, m.IncludesBaseCanProcess())
}

func TestCanProcess_OnlyMappableAssets(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))

	tests := []struct {
		path string
		want bool
	}{
		{"/static/js/main.abc.js", true},
		{"/assets/app.mjs", true},
		{"/assets/app.css", true},
		{"/index.html", false},
		{"/api/users", false},
		// A map itself is handled by whoever fetched it, not re-entered here.
		{"/static/js/main.abc.js.map", false},
	}
	for _, tt := range tests {
		raw := []byte("GET " + tt.path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
		rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequest(raw), nil)
		assert.Equal(t, tt.want, m.CanProcess(rr), "CanProcess(%q)", tt.path)
	}
}

// TestScanPerRequest_ReferencedMapIngestsRoutes is the main path: a bundle names
// its map, the map carries original source, and the routes that source calls are
// fed back into the scan.
func TestScanPerRequest_ReferencedMapIngestsRoutes(t *testing.T) {
	t.Parallel()
	mapBody := mapWithSources(t, true, "/api/v1/accounts", "/api/v1/devices")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".map") {
			// The static-host default: JSON served as a generic binary type.
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(mapBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	feeder := &recordingFeeder{}
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/main.abc.js"),
		"text/javascript",
		"(()=>{})();\n//# sourceMappingURL=main.abc.js.map\n",
	)

	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	require.Len(t, results, 1)

	event := results[0]
	assert.Equal(t, output.RecordKindFinding, event.RecordKind)
	assert.Equal(t, severity.Medium, event.Info.Severity, "embedded original source is a source disclosure")
	assert.Equal(t, output.EvidenceGradeImpact, event.EvidenceGrade)
	assert.Equal(t, "comment", event.Metadata["reference_origin"])
	assert.Equal(t, true, event.Metadata["has_source_content"])

	fed := feeder.urls()
	assert.Contains(t, fed, srv.URL+"/api/v1/accounts")
	assert.Contains(t, fed, srv.URL+"/api/v1/devices")
}

// TestScanPerRequest_HiddenSourceMap covers the case no reference extraction can
// reach: the build stripped the comment but still deployed the map.
func TestScanPerRequest_HiddenSourceMap(t *testing.T) {
	t.Parallel()
	mapBody := mapWithSources(t, true, "/api/internal/admin")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mapBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	feeder := &recordingFeeder{}
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/hidden.abc.js"),
		"text/javascript",
		"(()=>{})();\n", // no sourceMappingURL at all
	)

	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sibling-guess", results[0].Metadata["reference_origin"])
	assert.Contains(t, results[0].Info.Description, "carries no sourceMappingURL reference")
	assert.Contains(t, feeder.urls(), srv.URL+"/api/internal/admin")
}

// TestScanPerRequest_InlineMapNeedsNoFetch: an inline data: map is the whole
// disclosure, already present in the body.
func TestScanPerRequest_InlineMapNeedsNoFetch(t *testing.T) {
	t.Parallel()
	mapBody := mapWithSources(t, true, "/api/inline/route")
	inline := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(mapBody))

	var fetched int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fetched++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	feeder := &recordingFeeder{}
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/inline.abc.js"),
		"text/javascript",
		"(()=>{})();\n//# sourceMappingURL="+inline+"\n",
	)

	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, feeder.urls(), srv.URL+"/api/inline/route")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, fetched, "an inline map must not cost a request")
}

// TestScanPerRequest_CatchAllHTML_NoFalsePositive: a host answering 200 with its
// SPA shell for every path must not be reported as exposing a source map.
func TestScanPerRequest_CatchAllHTML_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>app shell ` + r.URL.Path + `</body></html>`))
	}))
	defer srv.Close()

	feeder := &recordingFeeder{}
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/app.abc.js"),
		"text/javascript",
		"(()=>{})();\n//# sourceMappingURL=app.abc.js.map\n",
	)

	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	assert.Empty(t, results, "a catch-all shell is not a source map")
	assert.Empty(t, feeder.urls(), "nothing may be ingested from a shell")
}

// TestScanPerRequest_ContentlessMapIsLowerSeverity: a map stripped of
// sourcesContent discloses layout, not source, and is graded accordingly.
func TestScanPerRequest_ContentlessMapIsLowerSeverity(t *testing.T) {
	t.Parallel()
	mapBody := mapWithSources(t, false)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".map") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mapBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/static/js/stripped.abc.js"),
		"text/javascript",
		"(()=>{})();\n//# sourceMappingURL=stripped.abc.js.map\n",
	)

	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.Low, results[0].Info.Severity)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, false, results[0].Metadata["has_source_content"])
	assert.Contains(t, results[0].Info.Description, "internal layout")
}

// TestBuildPathsNeverReachTheScanQueue asserts the end state, not one half of it:
// developer-machine paths must not be requested against the deployed host. Most
// are dropped by linkfinder's own unwantedExts/node_modules filtering, so this
// goes through ExtractPaths exactly as feedRecoveredRoutes does — a test of
// looksLikeBuildPath alone would pass while the real filter regressed.
func TestBuildPathsNeverReachTheScanQueue(t *testing.T) {
	source := []byte(`
		import x from "/src/index.ts";
		import y from "/node_modules/react/index.js";
		import z from "/client/src/App.tsx";
		import c from "/styles/theme.scss";
		import s from "/ui/Widget.svelte";
		fetch("/api/v1/users"); fetch("/admin"); fetch("/login");
	`)

	kept := map[string]bool{}
	for _, p := range linkfinder.ExtractPaths(source) {
		if strings.HasPrefix(p, "/") && !looksLikeBuildPath(p) {
			kept[p] = true
		}
	}

	for _, buildPath := range []string{
		"/src/index.ts", "/node_modules/react/index.js", "/client/src/App.tsx",
		"/styles/theme.scss", "/ui/Widget.svelte",
	} {
		assert.False(t, kept[buildPath], "%q is a build path and must not be queued", buildPath)
	}
	for _, route := range []string{"/api/v1/users", "/admin", "/login"} {
		assert.True(t, kept[route], "%q is a real route and must survive", route)
	}
}
