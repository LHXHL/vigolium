package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/agent/recon"
)

// fingerprintFixture is an origin with a page, a linked icon, robots.txt, a
// reflective CORS policy, an Allow header, a 404 for /missing.txt, and a soft
// 404: every other unknown path answers 200 with the same "not found" page.
type fingerprintFixture struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods map[string]int
	hits    int
}

var fixtureIcon = []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("icon-bytes", 20))

func newFingerprintFixture(t *testing.T) *fingerprintFixture {
	t.Helper()
	f := &fingerprintFixture{methods: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods[r.Method]++
		f.hits++
		f.mu.Unlock()
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Server", "fixture/1.0")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Fixture App</title><link rel="icon" href="/static/icon.png"></head><body>home</body></html>`))
		case "/static/icon.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(fixtureIcon)
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		case "/missing.txt":
			http.NotFound(w, r)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>About us</title></head><body><h1>About</h1><p>a real page with different content</p></body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Page not found</title></head><body>Sorry, nothing here.</body></html>`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestFingerprintStoresHostFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	assert.Equal(t, "fingerprint", doc["command"])
	items := doc["items"].([]any)
	require.Len(t, items, 1, "one origin")
	host := items[0].(map[string]any)
	assert.Equal(t, "Fixture App", host["title"])
	assert.Equal(t, "fixture/1.0", host["server"])
	assert.EqualValues(t, recon.ShodanFaviconHash(fixtureIcon), host["favicon_mmh3"])
	assert.Equal(t, true, host["soft_not_found"])
	fp := host["fingerprint"].(map[string]any)
	assert.Equal(t, "standard", fp["depth"])
	require.NotNil(t, fp["cors"])
	assert.Equal(t, true, fp["cors"].(map[string]any)["reflective"])

	f.mu.Lock()
	methods := map[string]int{}
	for k, v := range f.methods {
		methods[k] = v
	}
	hits := f.hits
	f.mu.Unlock()
	for m := range methods {
		assert.Contains(t, []string{"GET", "HEAD", "OPTIONS", "POST"}, m, "only reads are sent")
	}

	// Every request the phase sent is a stored record, source fingerprint.
	code, stdout, stderr = runA3(t, home, "traffic", "-j", "--compact", "--source", "fingerprint", "--all", "--fields", "uuid")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	stored := oneDoc(t, stdout, stderr)["total"].(float64)
	assert.Positive(t, stored)
	assert.LessOrEqual(t, int(stored), hits, "never more records than requests the origin saw")

	// The not-found baseline separates a real page from the soft-404 template,
	// and counts a genuine 404 as not found.
	code, stdout, stderr = runA3(t, home, "hosts", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	nf := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)["not_found"].(map[string]any)
	assert.EqualValues(t, 200, nf["status"])
	assert.NotEmpty(t, nf["signature"])
}

func TestFingerprintLightDepthAndBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	f.mu.Lock()
	light := f.hits
	f.hits = 0
	f.mu.Unlock()
	assert.LessOrEqual(t, light, 14, "light depth stays near nine reads (plus the scheme/preflight checks)")

	code, stdout, stderr = runA3(t, home, "fingerprint", "-t", f.srv.URL, "--max-requests-per-host", "5", "-j")
	f.mu.Lock()
	budgeted := f.hits
	f.mu.Unlock()
	assert.LessOrEqual(t, budgeted, 6, "the request budget holds for the phase (stdout:\n%s\nstderr:\n%s)", stdout, stderr)
	_ = code

	code, _, _ = runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "deep")
	assert.Equal(t, 2, code, "an unknown depth is a usage error")
}

func TestFingerprintRefusesOutOfScopeTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "nomatch.example")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "-j")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Zero(t, f.hits, "an out-of-scope target is refused before any request")
}

// After a fingerprint, traffic rows say whether they are the origin's
// not-found page: the soft-404 template and a real 404 are, a real page is not.
func TestTrafficMatchesNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	list := t.TempDir() + "/urls.txt"
	require.NoError(t, writeFile(list, f.srv.URL+"/no-such-page-xyz\n"+f.srv.URL+"/missing.txt\n"+f.srv.URL+"/about\n"))
	code, stdout, stderr = runA3(t, home, "ingest", "-i", list, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	urls := []string{"--url", f.srv.URL + "/no-such-page-xyz", "--url", f.srv.URL + "/missing.txt", "--url", f.srv.URL + "/about"}
	code, stdout, stderr = runA3(t, home, append([]string{"traffic", "-j", "--fields", "url,matches_not_found"}, urls...)...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	got := map[string]any{}
	for _, it := range oneDoc(t, stdout, stderr)["items"].([]any) {
		row := it.(map[string]any)
		u := row["url"].(string)
		got[u[strings.LastIndex(u, "/"):]] = row["matches_not_found"]
	}
	assert.Equal(t, true, got["/no-such-page-xyz"], "the soft-404 template is the not-found page")
	assert.Equal(t, true, got["/missing.txt"], "a 404 is not found")
	assert.Equal(t, false, got["/about"], "a real page is not")

	code, stdout, stderr = runA3(t, home, append([]string{"traffic", "-j", "--exclude-not-found", "--fields", "url"}, urls...)...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	assert.Len(t, doc["items"], 1)
	assert.EqualValues(t, 2, doc["not_found_excluded"])
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// Every entry point to a fingerprint-only run shapes the document as host
// facts: `--fields` takes the hosts vocabulary, and `run fingerprint` sets the
// depth with --fingerprint-depth.
func TestFingerprintDocumentShapesAsHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j", "--fields", "hostname,title,favicon_mmh3")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	row := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)
	assert.Len(t, row, 3)
	assert.Equal(t, "Fixture App", row["title"])

	code, stdout, stderr = runA3(t, home, "run", "fingerprint", "-t", f.srv.URL, "--fingerprint-depth", "light", "-j", "--compact")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	host := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "Fixture App", host["title"])
	assert.NotContains(t, host, "fingerprint", "--compact drops the nested report")
}
