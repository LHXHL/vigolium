package spider

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg/pathshape"
)

// Sitemap source.
//
// Discovery reads the sitemaps a site publishes (robots.txt "Sitemap:" lines,
// or /sitemap.xml and /sitemap_index.xml when robots names none) and turns
// their <loc> entries into spider links. A sitemap can list tens of thousands
// of URLs that mostly differ only in a record id, so the parser streams (it
// never holds the document), every input is size-capped, and the URLs that
// get fetched are a path-shape sample (SitemapSampler) rather than the list.

const (
	// SitemapMaxDecompressedBytes caps how much (decompressed) sitemap content
	// one document may yield. Past it the parse stops with ErrSitemapTooLarge.
	SitemapMaxDecompressedBytes = 50 << 20

	// SitemapMaxGzipRatio is the gzip bomb guard: once a document has expanded
	// past sitemapRatioFloorBytes, output larger than this multiple of the
	// compressed input read so far stops the parse with ErrSitemapBomb. Real
	// sitemaps compress roughly 5-30x; a bomb is hundreds to thousands.
	SitemapMaxGzipRatio = 100

	// SitemapMaxLocsPerDocument is the sitemap protocol's own per-file ceiling
	// (50,000 URLs). Past it the parse stops with ErrSitemapLocLimit.
	SitemapMaxLocsPerDocument = 50_000

	// SitemapMaxIndexDepth bounds <sitemapindex> nesting: a root document is
	// depth 1, its children depth 2, and a child that is itself an index is
	// not followed further.
	SitemapMaxIndexDepth = 2

	// SitemapMaxIndexChildren bounds how many child sitemaps one index may
	// contribute.
	SitemapMaxIndexChildren = 16

	sitemapRatioFloorBytes = 1 << 20
	sitemapMaxLocBytes     = 8 << 10 // longer <loc> values / text lines are skipped
	sitemapMaxXMLDepth     = 64      // element nesting guard for hostile XML
)

var (
	// ErrSitemapTooLarge reports a document that exceeded SitemapMaxDecompressedBytes.
	ErrSitemapTooLarge = errors.New("sitemap: content exceeds the decompressed size cap")
	// ErrSitemapBomb reports a gzip stream that tripped the expansion-ratio guard.
	ErrSitemapBomb = errors.New("sitemap: gzip expansion ratio exceeds the guard")
	// ErrSitemapLocLimit reports a document with more than SitemapMaxLocsPerDocument entries.
	ErrSitemapLocLimit = errors.New("sitemap: per-document <loc> limit reached")
)

// IsSitemapLimit reports whether err means a hard cap cut a document short
// (as opposed to a malformed or unreadable one). Entries read before the cap
// were still delivered.
func IsSitemapLimit(err error) bool {
	return errors.Is(err, ErrSitemapTooLarge) || errors.Is(err, ErrSitemapBomb) || errors.Is(err, ErrSitemapLocLimit)
}

// SitemapKind is the format of a parsed sitemap document.
type SitemapKind uint8

const (
	SitemapUnknown SitemapKind = iota // not a sitemap (e.g. an HTML soft-404)
	SitemapURLSet                     // <urlset>: <loc> entries are pages
	SitemapIndex                      // <sitemapindex>: <loc> entries are child sitemaps
	SitemapText                       // plain text, one absolute URL per line
)

// String returns the format name.
func (k SitemapKind) String() string {
	switch k {
	case SitemapURLSet:
		return "urlset"
	case SitemapIndex:
		return "sitemapindex"
	case SitemapText:
		return "text"
	default:
		return "unknown"
	}
}

// ParseSitemap streams one sitemap document and calls fn for each <loc> (or
// text line) in document order. A gzip stream is recognised by its 1f8b magic,
// whatever the URL suffix: a ".gz" URL the transport already decoded parses as
// plain content. fn returning false stops the parse early with a nil error.
//
// The returned kind is known once the root element (or first byte) is read.
// An error after entries were delivered leaves those entries valid: a
// malformed tail still yields the locs before it, and IsSitemapLimit(err)
// tells a cap from a parse failure.
func ParseSitemap(r io.Reader, fn func(kind SitemapKind, loc string) bool) (SitemapKind, error) {
	guard, err := openSitemapStream(r)
	if err != nil {
		return SitemapUnknown, err
	}
	br := bufio.NewReaderSize(guard, sitemapMaxLocBytes)

	first, err := firstSignificantByte(br)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return SitemapUnknown, nil
		}
		return SitemapUnknown, guard.cause(err)
	}
	if first == '<' {
		kind, err := parseXMLSitemap(br, fn)
		return kind, guard.cause(err)
	}
	return SitemapText, guard.cause(parseTextSitemap(br, fn))
}

// expansionGuard enforces the decompressed size cap and, for gzip input, the
// expansion-ratio guard.
type expansionGuard struct {
	r          io.Reader
	compressed *countingReader // nil for plain input
	n          int64
	tripped    error
}

func (g *expansionGuard) Read(p []byte) (int, error) {
	if g.tripped != nil {
		return 0, g.tripped
	}
	n, err := g.r.Read(p)
	g.n += int64(n)
	if g.n > SitemapMaxDecompressedBytes {
		n -= int(g.n - SitemapMaxDecompressedBytes)
		g.n = SitemapMaxDecompressedBytes
		g.tripped = ErrSitemapTooLarge
		return n, g.tripped
	}
	if g.compressed != nil && g.n > sitemapRatioFloorBytes &&
		g.n > SitemapMaxGzipRatio*max(g.compressed.n, 1) {
		g.tripped = ErrSitemapBomb
		return n, g.tripped
	}
	return n, err
}

// cause prefers the guard's own error: encoding/xml and bufio may surface a
// guard trip as a generic read or syntax error.
func (g *expansionGuard) cause(err error) error {
	if err == nil {
		return nil
	}
	if g.tripped != nil {
		return g.tripped
	}
	return err
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// openSitemapStream wraps r with gzip decoding (when the stream starts with the
// gzip magic) and the expansion guard.
func openSitemapStream(r io.Reader) (*expansionGuard, error) {
	cr := &countingReader{r: r}
	br := bufio.NewReader(cr)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("sitemap: gzip header: %w", err)
		}
		return &expansionGuard{r: gz, compressed: cr}, nil
	}
	return &expansionGuard{r: br}, nil
}

// firstSignificantByte skips leading whitespace and a UTF-8 BOM and returns
// (without consuming) the first content byte.
func firstSignificantByte(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case 0xEF:
			if rest, _ := br.Peek(2); len(rest) == 2 && rest[0] == 0xBB && rest[1] == 0xBF {
				_, _ = br.Discard(2)
				continue
			}
		}
		_ = br.UnreadByte()
		return b, nil
	}
}

// parseXMLSitemap walks the XML token stream. Only a <loc> that is a direct
// child of <url> (in a <urlset>) or <sitemap> (in a <sitemapindex>) counts, so
// image:loc / video:loc / xhtml:link extensions are ignored. Any other root
// element (an HTML page, an RSS feed) is SitemapUnknown with no entries.
func parseXMLSitemap(r io.Reader, fn func(SitemapKind, string) bool) (SitemapKind, error) {
	dec := xml.NewDecoder(r)
	// Lenient: real sitemaps carry unescaped "&" in URLs and odd charsets
	// labels. URLs are ASCII in practice, so any declared charset passes through.
	dec.Strict = false
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }

	var (
		kind     SitemapKind
		stack    []string
		inLoc    bool
		overflow bool
		loc      strings.Builder
		count    int
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return kind, nil
			}
			return kind, fmt.Errorf("sitemap: malformed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if len(stack) == 0 {
				switch name {
				case "urlset":
					kind = SitemapURLSet
				case "sitemapindex":
					kind = SitemapIndex
				default:
					return SitemapUnknown, nil
				}
			}
			if name == "loc" && len(stack) == 2 &&
				((kind == SitemapURLSet && stack[1] == "url") || (kind == SitemapIndex && stack[1] == "sitemap")) {
				inLoc, overflow = true, false
				loc.Reset()
			}
			stack = append(stack, name)
			if len(stack) > sitemapMaxXMLDepth {
				return kind, errors.New("sitemap: malformed XML: nesting too deep")
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if !inLoc || !strings.EqualFold(t.Name.Local, "loc") {
				continue
			}
			inLoc = false
			v := strings.TrimSpace(loc.String())
			if v == "" || overflow {
				continue
			}
			count++
			if !fn(kind, v) {
				return kind, nil
			}
			if count >= SitemapMaxLocsPerDocument {
				return kind, ErrSitemapLocLimit
			}
		case xml.CharData:
			if inLoc {
				if loc.Len()+len(t) > sitemapMaxLocBytes {
					overflow = true
				} else {
					loc.Write(t)
				}
			}
		}
	}
}

// parseTextSitemap reads one absolute http(s) URL per line; anything else
// (blank lines, comments, prose) is skipped, as are over-long lines.
func parseTextSitemap(br *bufio.Reader, fn func(SitemapKind, string) bool) error {
	count := 0
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			continue
		}
		if v := string(bytes.TrimSpace(line)); isAbsoluteHTTPURL(v) {
			count++
			if !fn(SitemapText, v) {
				return nil
			}
			if count >= SitemapMaxLocsPerDocument {
				return ErrSitemapLocLimit
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func isAbsoluteHTTPURL(s string) bool {
	if len(s) < len("http://x") || strings.ContainsAny(s, " \t") {
		return false
	}
	lower := strings.ToLower(s[:8])
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// SitemapExtractor turns a sitemap document into spider links: a <urlset> or
// text sitemap yields page links (ResourceHTML), a <sitemapindex> yields child
// sitemap links (ResourceSitemap). Every link carries SourceSitemap.
//
// Extract is the LinkExtractor form and only acts on responses whose URL looks
// like a sitemap; discovery calls ExtractDeclared for documents robots.txt or
// an index named, whatever their path. Neither scope-checks nor samples: the
// caller owns scope and volume (see SitemapSampler).
type SitemapExtractor struct {
	urlResolver *URLResolver
}

// NewSitemapExtractor creates a sitemap extractor.
func NewSitemapExtractor(urlResolver *URLResolver) *SitemapExtractor {
	return &SitemapExtractor{urlResolver: urlResolver}
}

// Extract parses response as a sitemap when its URL path names one
// (".../sitemap...", or a .xml / .xml.gz file whose root is a sitemap element).
func (x *SitemapExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	if response == nil || response.URL == nil || !looksLikeSitemapURL(response.URL) {
		return nil
	}
	_, err := x.ExtractDeclared(ctx, response.URL, response.Body, callback)
	return err
}

// ExtractDeclared parses body as the sitemap at docURL (relative locs resolve
// against it) and reports each entry. It returns the document kind; the error
// semantics are ParseSitemap's.
func (x *SitemapExtractor) ExtractDeclared(ctx context.Context, docURL *url.URL, body []byte, callback LinkCallback) (SitemapKind, error) {
	if len(body) == 0 {
		return SitemapUnknown, nil
	}
	return ParseSitemap(bytes.NewReader(body), func(kind SitemapKind, loc string) bool {
		if ctx.Err() != nil {
			return false
		}
		u := x.resolve(docURL, loc)
		if u == nil {
			return true
		}
		rt := ResourceHTML
		if kind == SitemapIndex {
			rt = ResourceSitemap
		}
		callback(&DiscoveredLink{
			SourceType:   SourceSitemap,
			URL:          u,
			RawURL:       loc,
			ResourceType: rt,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "sitemap",
		})
		return true
	})
}

func (x *SitemapExtractor) resolve(docURL *url.URL, loc string) *url.URL {
	var (
		u   *url.URL
		err error
	)
	if x.urlResolver != nil && docURL != nil {
		u, err = x.urlResolver.Resolve(docURL, loc)
	} else {
		u, err = url.Parse(loc)
	}
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil
	}
	return u
}

func looksLikeSitemapURL(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "sitemap") &&
		(strings.HasSuffix(p, ".xml") || strings.HasSuffix(p, ".xml.gz") ||
			strings.HasSuffix(p, ".txt") || strings.HasSuffix(p, ".gz"))
}

// SitemapURLs returns the Sitemap: URLs a robots.txt body declares, resolved
// against robotsURL (which must be the /robots.txt URL).
func (p *RobotsTxtParser) SitemapURLs(robotsURL *url.URL, body []byte) []*url.URL {
	var out []*url.URL
	_ = p.Extract(context.Background(), robotsURL, NewHTTPResponse(robotsURL, nil, body, 0), func(link *DiscoveredLink) {
		if link.ResourceType == ResourceSitemap && link.URL != nil {
			out = append(out, link.URL)
		}
	})
	return out
}

// SitemapSampler picks which sitemap locs get spidered. URLs are grouped by
// shape (host + pathshape template + sorted query names), at most perShape are
// kept per shape, and Sample takes them round-robin across shapes (in
// first-seen order) up to maxURLs, so 40,000 /product/{int} pages cost three
// requests and never crowd out /about or /careers.
//
// Memory is bounded by maxURLs*perShape: once maxURLs shapes exist, a new
// shape could never be reached by the first round-robin pass, so it is
// dropped (and counted in Capped) instead of stored.
type SitemapSampler struct {
	perShape, maxURLs int

	buckets map[string][]*url.URL
	order   []string
	kept    int // URLs held in buckets

	offered      int // URLs passed to Add
	shapeSkipped int // dropped by the per-shape budget (sampling, not a cap)
	overflow     int // dropped because maxURLs shapes already existed
}

// NewSitemapSampler creates a sampler; non-positive arguments fall back to 3
// per shape and 2000 total.
func NewSitemapSampler(perShape, maxURLs int) *SitemapSampler {
	if perShape <= 0 {
		perShape = 3
	}
	if maxURLs <= 0 {
		maxURLs = 2000
	}
	return &SitemapSampler{perShape: perShape, maxURLs: maxURLs, buckets: make(map[string][]*url.URL)}
}

// Add offers one (already scope-checked) URL to the sample.
func (s *SitemapSampler) Add(u *url.URL) {
	if u == nil {
		return
	}
	s.offered++
	key := sitemapShapeKey(u)
	bucket, ok := s.buckets[key]
	if !ok && len(s.order) >= s.maxURLs {
		s.overflow++
		return
	}
	if len(bucket) >= s.perShape {
		s.shapeSkipped++
		return
	}
	str := u.String()
	for _, have := range bucket {
		if have.String() == str {
			s.shapeSkipped++ // duplicate of a held URL
			return
		}
	}
	if !ok {
		s.order = append(s.order, key)
	}
	s.buckets[key] = append(bucket, u)
	s.kept++
}

// Sample returns the selected URLs, round-robin over shapes.
func (s *SitemapSampler) Sample() []*url.URL {
	out := make([]*url.URL, 0, min(s.kept, s.maxURLs))
	for round := 0; len(out) < s.maxURLs; round++ {
		progressed := false
		for _, key := range s.order {
			bucket := s.buckets[key]
			if round >= len(bucket) {
				continue
			}
			out = append(out, bucket[round])
			progressed = true
			if len(out) >= s.maxURLs {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// Shapes is the number of distinct shapes held.
func (s *SitemapSampler) Shapes() int { return len(s.order) }

// Capped is the number of URLs that the per-shape sample would have taken but
// the maxURLs budget dropped. Above zero means the sitemap_cap limit was hit.
func (s *SitemapSampler) Capped() int {
	return s.overflow + max(0, s.kept-s.maxURLs)
}

// sitemapShapeKey groups URLs that reach the same endpoint with different
// record values. The scheme is ignored: http and https copies are one endpoint.
func sitemapShapeKey(u *url.URL) string {
	template, _ := pathshape.Shape(u.Path)
	if template == "" {
		template = "/"
	}
	var b strings.Builder
	b.WriteString(strings.ToLower(u.Host))
	b.WriteString(template)
	if u.RawQuery != "" {
		names := make([]string, 0, 4)
		for name := range u.Query() {
			names = append(names, name)
		}
		slices.Sort(names)
		b.WriteByte('?')
		b.WriteString(strings.Join(names, "&"))
	}
	return b.String()
}

// Ensure SitemapExtractor implements LinkExtractor.
var _ LinkExtractor = (*SitemapExtractor)(nil)
