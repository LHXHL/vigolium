package spider

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectSitemap(t *testing.T, r io.Reader) (SitemapKind, []string, error) {
	t.Helper()
	var locs []string
	kind, err := ParseSitemap(r, func(_ SitemapKind, loc string) bool {
		locs = append(locs, loc)
		return true
	})
	return kind, locs, err
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

const urlsetDoc = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc> https://example.com/about </loc>
    <lastmod>2024-01-01</lastmod>
    <image:image><image:loc>https://cdn.example.com/a.png</image:loc></image:image>
  </url>
  <url><loc>https://example.com/products/42?ref=a&amp;x=1</loc></url>
  <url><loc>https://example.com/search?q=a&b=2</loc></url>
</urlset>`

func TestParseSitemap_URLSet(t *testing.T) {
	kind, locs, err := collectSitemap(t, strings.NewReader(urlsetDoc))
	require.NoError(t, err)
	assert.Equal(t, SitemapURLSet, kind)
	// image:loc is not a direct <url> child; the unescaped "&" is tolerated.
	assert.Equal(t, []string{
		"https://example.com/about",
		"https://example.com/products/42?ref=a&x=1",
		"https://example.com/search?q=a&b=2",
	}, locs)
}

func TestParseSitemap_Index(t *testing.T) {
	doc := "\xEF\xBB\xBF" + `<?xml version="1.0" encoding="ISO-8859-1"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-products.xml.gz</loc><lastmod>2024</lastmod></sitemap>
</sitemapindex>`
	kind, locs, err := collectSitemap(t, strings.NewReader(doc))
	require.NoError(t, err)
	assert.Equal(t, SitemapIndex, kind)
	assert.Equal(t, []string{
		"https://example.com/sitemap-pages.xml",
		"https://example.com/sitemap-products.xml.gz",
	}, locs)
}

func TestParseSitemap_Gzip(t *testing.T) {
	kind, locs, err := collectSitemap(t, bytes.NewReader(gzipBytes(t, []byte(urlsetDoc))))
	require.NoError(t, err)
	assert.Equal(t, SitemapURLSet, kind)
	assert.Len(t, locs, 3)
}

func TestParseSitemap_Text(t *testing.T) {
	doc := "https://example.com/a\r\n\n# comment\nnot a url\nftp://example.com/x\n" +
		"https://example.com/" + strings.Repeat("x", sitemapMaxLocBytes*2) + "\n" +
		"  http://example.com/b  \nhttps://example.com/c"
	kind, locs, err := collectSitemap(t, strings.NewReader(doc))
	require.NoError(t, err)
	assert.Equal(t, SitemapText, kind)
	assert.Equal(t, []string{"https://example.com/a", "http://example.com/b", "https://example.com/c"}, locs)
}

func TestParseSitemap_NotASitemap(t *testing.T) {
	for name, doc := range map[string]string{
		"html soft-404": "<!DOCTYPE html><html><body><a href=\"https://example.com/x\">x</a></body></html>",
		"rss":           "<rss><channel><item><link>https://example.com/x</link></item></channel></rss>",
		"empty":         "   \n",
	} {
		t.Run(name, func(t *testing.T) {
			_, locs, err := collectSitemap(t, strings.NewReader(doc))
			require.NoError(t, err)
			assert.Empty(t, locs)
		})
	}
}

func TestParseSitemap_MalformedKeepsPrefix(t *testing.T) {
	doc := `<urlset><url><loc>https://example.com/one</loc></url><url><loc>https://example.com/two</loc></url><url><loc>https://exa`
	kind, locs, err := collectSitemap(t, strings.NewReader(doc))
	require.Error(t, err)
	assert.False(t, IsSitemapLimit(err), "a truncated document is malformed, not capped")
	assert.Equal(t, SitemapURLSet, kind)
	assert.Equal(t, []string{"https://example.com/one", "https://example.com/two"}, locs)
}

func TestParseSitemap_StopEarly(t *testing.T) {
	n := 0
	_, err := ParseSitemap(strings.NewReader(urlsetDoc), func(SitemapKind, string) bool {
		n++
		return false
	})
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestParseSitemap_GzipBomb(t *testing.T) {
	// 64 MiB of zeros compresses to ~64 KiB: a ~1000x ratio.
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	require.NoError(t, err)
	_, err = zw.Write([]byte("<urlset><url><loc>https://example.com/a</loc></url>"))
	require.NoError(t, err)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 64; i++ {
		_, err = zw.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	_, locs, err := collectSitemap(t, bytes.NewReader(buf.Bytes()))
	require.ErrorIs(t, err, ErrSitemapBomb)
	assert.True(t, IsSitemapLimit(err))
	assert.Equal(t, []string{"https://example.com/a"}, locs, "entries before the trip survive")
}

// endlessReader yields prefix, then the filler byte forever.
type endlessReader struct {
	prefix []byte
	filler byte
}

func (r *endlessReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	for i := range p {
		p[i] = r.filler
	}
	return len(p), nil
}

func TestParseSitemap_DecompressedSizeCap(t *testing.T) {
	r := &endlessReader{prefix: []byte("<urlset><url><loc>https://example.com/a</loc></url>"), filler: ' '}
	_, locs, err := collectSitemap(t, r)
	require.ErrorIs(t, err, ErrSitemapTooLarge)
	assert.Len(t, locs, 1)
}

// locStream generates a <urlset> with n entries without materialising it.
func locStream(n int) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "<urlset>")
		for i := 0; i < n; i++ {
			_, _ = fmt.Fprintf(pw, "<url><loc>https://example.com/p/%d</loc></url>", i)
		}
		_, _ = io.WriteString(pw, "</urlset>")
		_ = pw.Close()
	}()
	return pr
}

func TestParseSitemap_LocLimit(t *testing.T) {
	_, locs, err := collectSitemap(t, locStream(SitemapMaxLocsPerDocument+10))
	require.ErrorIs(t, err, ErrSitemapLocLimit)
	assert.Len(t, locs, SitemapMaxLocsPerDocument)
}

func TestSitemapExtractor(t *testing.T) {
	x := NewSitemapExtractor(NewURLResolver())
	doc := mustParseURL("https://example.com/sitemap_index.xml")
	index := `<sitemapindex><sitemap><loc>/sitemap-1.xml</loc></sitemap><sitemap><loc>javascript:alert(1)</loc></sitemap></sitemapindex>`

	var links []*DiscoveredLink
	kind, err := x.ExtractDeclared(context.Background(), doc, []byte(index), func(l *DiscoveredLink) { links = append(links, l) })
	require.NoError(t, err)
	assert.Equal(t, SitemapIndex, kind)
	require.Len(t, links, 1, "relative locs resolve, non-http locs are dropped")
	assert.Equal(t, "https://example.com/sitemap-1.xml", links[0].URL.String())
	assert.Equal(t, ResourceSitemap, links[0].ResourceType)
	assert.Equal(t, SourceSitemap, links[0].SourceType)

	links = nil
	_, err = x.ExtractDeclared(context.Background(), doc, []byte(urlsetDoc), func(l *DiscoveredLink) { links = append(links, l) })
	require.NoError(t, err)
	require.Len(t, links, 3)
	assert.Equal(t, ResourceHTML, links[0].ResourceType)

	// The LinkExtractor form only acts on sitemap-looking URLs.
	links = nil
	page := mustParseURL("https://example.com/notes.txt")
	require.NoError(t, x.Extract(context.Background(), page, &HTTPResponse{URL: page, Body: []byte("https://example.com/a\n")},
		func(l *DiscoveredLink) { links = append(links, l) }))
	assert.Empty(t, links)
	txt := mustParseURL("https://example.com/sitemap.txt")
	require.NoError(t, x.Extract(context.Background(), txt, &HTTPResponse{URL: txt, Body: []byte("https://example.com/a\n")},
		func(l *DiscoveredLink) { links = append(links, l) }))
	assert.Len(t, links, 1)
}

func TestRobotsTxtParser_SitemapURLs(t *testing.T) {
	p := NewRobotsTxtParser(NewURLResolver())
	robots := mustParseURL("https://example.com/robots.txt")
	got := p.SitemapURLs(robots, []byte("User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sm.xml\nsitemap: /news.xml.gz\n"))
	require.Len(t, got, 2)
	assert.Equal(t, "https://example.com/sm.xml", got[0].String())
	assert.Equal(t, "https://example.com/news.xml.gz", got[1].String())
}

func TestSitemapSampler_PerShapeAndRoundRobin(t *testing.T) {
	s := NewSitemapSampler(3, 5)
	for i := 0; i < 100; i++ {
		s.Add(mustParseURL(fmt.Sprintf("https://example.com/product/%d", i)))
	}
	s.Add(mustParseURL("https://example.com/about"))
	s.Add(mustParseURL("https://example.com/about")) // duplicate
	s.Add(mustParseURL("https://example.com/careers"))

	got := urlStrings(s.Sample())
	// Round 1 takes one per shape in first-seen order, round 2 the next product.
	assert.Equal(t, []string{
		"https://example.com/product/0",
		"https://example.com/about",
		"https://example.com/careers",
		"https://example.com/product/1",
	}, got[:4])
	assert.Len(t, got, 5)
	assert.Equal(t, 103, s.Offered())
	assert.Equal(t, 3, s.Shapes())
	// 3 products + about + careers held = 5 = maxURLs, so nothing was capped:
	// the other 97 products are shape sampling, not a budget.
	assert.Equal(t, 0, s.Capped())
}

func TestSitemapSampler_Cap(t *testing.T) {
	// Slugs never collapse, so each is its own shape.
	s := NewSitemapSampler(3, 10)
	for i := 0; i < 50; i++ {
		s.Add(mustParseURL(fmt.Sprintf("https://example.com/blog/post-title-%c%c", 'a'+i%26, 'a'+i/26)))
	}
	assert.Len(t, s.Sample(), 10)
	assert.Equal(t, 10, s.Shapes(), "shapes past the budget are not stored")
	assert.Equal(t, 40, s.Capped())
}

func TestSitemapSampler_QueryNamesAreShape(t *testing.T) {
	s := NewSitemapSampler(1, 10)
	s.Add(mustParseURL("https://example.com/view?id=1"))
	s.Add(mustParseURL("https://example.com/view?id=2"))
	s.Add(mustParseURL("https://example.com/view?id=2&tab=x"))
	s.Add(mustParseURL("https://other.example.com/view?id=1"))
	assert.Len(t, s.Sample(), 3)
}

func urlStrings(us []*url.URL) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	return out
}
