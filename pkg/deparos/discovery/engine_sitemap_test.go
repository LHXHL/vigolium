package discovery

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// sitemapTestServer serves the given path → body map (404 elsewhere) and
// records every path requested.
type sitemapTestServer struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func newSitemapTestServer(t *testing.T, routes func(base string) map[string][]byte) *sitemapTestServer {
	t.Helper()
	s := &sitemapTestServer{hits: map[string]int{}}
	var bodies map[string][]byte
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		if body, ok := bodies[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	bodies = routes(s.URL)
	t.Cleanup(s.Close)
	return s
}

func (s *sitemapTestServer) hit(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func sitemapEngine(t *testing.T, startURL string, sm config.SitemapConfig) *Engine {
	t.Helper()
	cfg := &config.Config{
		Target: config.TargetConfig{
			StartURL:  startURL,
			Mode:      config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{Enabled: true, MaxDepth: 16},
			ScopeMode: "exact",
		},
		Engine: config.EngineConfig{
			CaseSensitivity:  config.CaseSensitive,
			DiscoveryThreads: 4,
			Timeout:          10 * time.Second,
		},
		Sitemap: sm,
	}
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	t.Cleanup(engine.Stop)
	return engine
}

func sampledPaths(out sitemapOutcome) []string {
	paths := make([]string, 0, len(out.Sampled))
	for _, u := range out.Sampled {
		paths = append(paths, u.Path)
	}
	return paths
}

func TestFetchSitemaps_RobotsNamedSitemapQueuesSample(t *testing.T) {
	srv := newSitemapTestServer(t, func(base string) map[string][]byte {
		var urlset strings.Builder
		urlset.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
		for i := 1; i <= 20; i++ {
			fmt.Fprintf(&urlset, "<url><loc>%s/product/%d</loc></url>", base, i)
		}
		fmt.Fprintf(&urlset, "<url><loc>%s/about-us</loc></url>", base)
		urlset.WriteString("<url><loc>https://elsewhere.example/off-scope</loc></url>")
		urlset.WriteString("</urlset>")
		return map[string][]byte{
			"/robots.txt":     []byte("User-agent: *\nSitemap: " + base + "/maps/pages.xml\n"),
			"/maps/pages.xml": []byte(urlset.String()),
		}
	})
	engine := sitemapEngine(t, srv.URL, config.SitemapConfig{Enabled: true, FollowIndex: true})
	base, _ := url.Parse(srv.URL)

	named := engine.loadRobotsTxt(base)
	require.Len(t, named, 1)
	before := engine.taskQueue.Size()
	out := engine.fetchSitemaps(base, named)

	assert.Equal(t, 1, out.Documents)
	assert.Equal(t, 21, out.Locs, "every in-scope loc is read")
	assert.Equal(t, 1, out.OutOfScope)
	assert.ElementsMatch(t, []string{"/product/1", "/about-us", "/product/2", "/product/3"}, sampledPaths(out),
		"3 per path shape plus the distinct page")
	assert.Zero(t, out.Capped)
	assert.Zero(t, engine.SitemapCapped())
	assert.Greater(t, engine.taskQueue.Size(), before, "sampled locs are queued as spider tasks")
	assert.Zero(t, srv.hit("/sitemap.xml"), "robots named a sitemap, so no default probe")
	assert.Equal(t, 1, srv.hit("/maps/pages.xml"))

	// Every in-scope loc, sampled or not, feeds the observed-path wordlist.
	assert.True(t, engine.observedPaths.Contains([]byte("/product/17")))
	assert.False(t, engine.observedPaths.Contains([]byte("/off-scope")))
}

func TestFetchSitemaps_DefaultProbeAndIndex(t *testing.T) {
	srv := newSitemapTestServer(t, func(base string) map[string][]byte {
		return map[string][]byte{
			"/sitemap_index.xml": []byte(`<sitemapindex>` +
				`<sitemap><loc>` + base + `/sm/a.xml.gz</loc></sitemap>` +
				`<sitemap><loc>` + base + `/sm/nested.xml</loc></sitemap>` +
				`<sitemap><loc>https://elsewhere.example/sm.xml</loc></sitemap>` +
				`</sitemapindex>`),
			"/sm/a.xml.gz":     gzipBody(t, `<urlset><url><loc>`+base+`/from-gz</loc></url></urlset>`),
			"/sm/nested.xml":   []byte(`<sitemapindex><sitemap><loc>` + base + `/sm/too-deep.xml</loc></sitemap></sitemapindex>`),
			"/sm/too-deep.xml": []byte(`<urlset><url><loc>` + base + `/too-deep</loc></url></urlset>`),
		}
	})
	engine := sitemapEngine(t, srv.URL, config.SitemapConfig{Enabled: true, FollowIndex: true})
	base, _ := url.Parse(srv.URL)

	out := engine.fetchSitemaps(base, nil)
	assert.Equal(t, 1, srv.hit("/sitemap.xml"), "default probe")
	assert.Equal(t, 1, srv.hit("/sitemap_index.xml"), "default probe")
	assert.Equal(t, 1, srv.hit("/sm/a.xml.gz"))
	assert.Equal(t, 1, srv.hit("/sm/nested.xml"))
	assert.Zero(t, srv.hit("/sm/too-deep.xml"), "index depth is capped at 2")
	assert.Equal(t, []string{"/from-gz"}, sampledPaths(out))
	assert.Equal(t, 1, out.Capped, "the dropped grandchild is a cap")
	assert.Equal(t, 1, engine.SitemapCapped())
}

func TestFetchSitemaps_TenThousandEntriesStayUnderCap(t *testing.T) {
	const entries = 10_000
	srv := newSitemapTestServer(t, func(base string) map[string][]byte {
		var b strings.Builder
		b.WriteString("<urlset>")
		for i := 0; i < entries; i++ {
			// Slugs never collapse to a shape, so every entry is its own shape.
			fmt.Fprintf(&b, "<url><loc>%s/blog/post-%c%c%c-title</loc></url>", base,
				'a'+i%26, 'a'+(i/26)%26, 'a'+(i/676)%26)
		}
		b.WriteString("</urlset>")
		return map[string][]byte{"/sitemap.xml": gzipBody(t, b.String())}
	})
	engine := sitemapEngine(t, srv.URL, config.SitemapConfig{Enabled: true, MaxURLs: 500})
	base, _ := url.Parse(srv.URL)

	out := engine.fetchSitemaps(base, nil)
	assert.Equal(t, entries, out.Locs)
	assert.Len(t, out.Sampled, 500, "never more than max_urls")
	assert.Equal(t, entries-500, out.Capped)
	assert.Equal(t, entries-500, engine.SitemapCapped(), "the cap is reported for sitemap_cap")
}

func TestFetchSitemaps_Disabled(t *testing.T) {
	srv := newSitemapTestServer(t, func(base string) map[string][]byte {
		return map[string][]byte{"/sitemap.xml": []byte(`<urlset><url><loc>` + base + `/x</loc></url></urlset>`)}
	})
	engine := sitemapEngine(t, srv.URL, config.SitemapConfig{})
	base, _ := url.Parse(srv.URL)

	out := engine.fetchSitemaps(base, nil)
	assert.Zero(t, out.Documents)
	assert.Zero(t, srv.hit("/sitemap.xml"))
}

func gzipBody(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
