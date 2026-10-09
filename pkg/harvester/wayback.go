package harvester

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sourcegraph/conc/pool"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

const (
	waybackBaseURL    = "http://web.archive.org"
	waybackTimeout    = 60 * time.Second
	waybackMaxRetries = 3
	waybackRetryDelay = 1 * time.Second
	waybackMaxBackoff = 4 * time.Second
)

// waybackAPIError represents an error from the Wayback Machine CDX API.
type waybackAPIError struct {
	StatusCode int
	Status     string
	URL        string
}

func (e *waybackAPIError) Error() string {
	return fmt.Sprintf("wayback API error: %s for %s", e.Status, e.URL)
}

// waybackClient fetches URLs from the Wayback Machine CDX API.
type waybackClient struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
	maxRetries int
	retryDelay time.Duration
	maxBackoff time.Duration

	// pageSize and maxRows bound the paged index query; zero means the
	// package default (see cdxBounds).
	pageSize int
	maxRows  int
}

func newWaybackClient(proxyURL ...string) *waybackClient {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &waybackClient{
		httpClient: NewHTTPClient(waybackTimeout, proxy),
		baseURL:    waybackBaseURL,
		userAgent:  httpmsg.DefaultUserAgent(),
		maxRetries: waybackMaxRetries,
		retryDelay: waybackRetryDelay,
		maxBackoff: waybackMaxBackoff,
	}
}

// fetch retrieves historical URLs for the given domain from Wayback Machine.
// It streams results line-by-line and sends each URL string to the results channel.
//
// The index query is only the first half. What a CDX index holds is the URLs a
// crawler happened to record; what it cannot hold is an endpoint that was only
// ever named inside a JavaScript bundle, or a path a site owner listed in
// robots.txt precisely so no crawler would follow it. Both are recoverable,
// because the archive also serves the captured bodies — see mine.
func (c *waybackClient) fetch(ctx context.Context, domain string, results chan<- Result, sourceName string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	rows, err := c.fetchIndex(ctx, domain, results, sourceName)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && len(rows) == 0 {
		return err
	}

	// A later index page failing still leaves the rows earlier pages
	// produced worth mining; the error is reported after.
	c.mine(ctx, domain, rows, results, sourceName)
	return err
}

// cdxMimeExclusion drops index rows whose content cannot carry an endpoint.
// statuscode is filtered to "not 404" only: 301/302/401/403 rows are real
// endpoints, and the mining pass reads the status itself.
const (
	cdxStatusFilter  = "!statuscode:404"
	cdxMimeExclusion = "!mimetype:(image|font|video|audio)/.*"

	// cdxMaxEmptyPages stops paging when the server keeps handing out resume
	// keys for pages with no rows (every row in the block filtered or
	// collapsed away) — progress that never arrives is a loop.
	cdxMaxEmptyPages = 3
)

// cdxBounds resolves the page size and row cap; a zero field (a client built
// without setCDXBounds) means the package default, and a resolved row cap of 0
// means unbounded.
func (c *waybackClient) cdxBounds() (pageSize, maxRows int) {
	pageSize, maxRows = c.pageSize, c.maxRows
	if pageSize <= 0 {
		pageSize = DefaultCDXPageSize
	}
	if maxRows == 0 {
		maxRows = DefaultCDXMaxRows
	}
	if maxRows < 0 {
		maxRows = 0
	}
	return pageSize, maxRows
}

// indexURL renders one page of the domain index query. collapse=urlkey keeps
// one row per URL; the filters are applied server side so excluded rows never
// cross the wire. resumeKey is passed verbatim: the server prints it already
// URL-encoded and expects it back exactly as printed.
func (c *waybackClient) indexURL(domain string, pageSize int, resumeKey string, paged bool) string {
	// timestamp, mimetype and statuscode ride along with the URL the index
	// already returned: they cost nothing extra on the wire and they are what
	// lets the mining pass replay a capture and skip the ones with no body.
	apiURL := fmt.Sprintf("%s/cdx/search/cdx?url=*.%s/*&output=txt&fl=original,timestamp,mimetype,statuscode&collapse=urlkey&filter=%s&filter=%s",
		c.baseURL, domain, url.QueryEscape(cdxStatusFilter), url.QueryEscape(cdxMimeExclusion))
	if !paged {
		return apiURL
	}
	apiURL += fmt.Sprintf("&showResumeKey=true&limit=%d", pageSize)
	if resumeKey != "" {
		apiURL += "&resumeKey=" + resumeKey
	}
	return apiURL
}

// fetchIndex streams the CDX index page by page, emitting every URL it reports
// and returning the mineable rows so the mining pass can choose what to read.
//
// Paging follows the CDX resumption protocol: each page asks for
// showResumeKey=true&limit=<page_size>, and the server ends a page that has
// more behind it with a blank line and the key to resume from. Paging stops
// when no key comes back, at the max_rows cap (reported as a LimitCDXMaxRows
// Result), or on a repeated key / run of empty pages.
//
// Fallback: a server that ignores showResumeKey returns a full first page and
// no key. That looks exactly like "done", so a first page that came back full
// without a key is re-read once unpaged — the pre-paging query — skipping the
// rows already emitted, bounded by the same row cap.
func (c *waybackClient) fetchIndex(ctx context.Context, domain string, results chan<- Result, sourceName string) ([]cdxRow, error) {
	pageSize, maxRows := c.cdxBounds()

	var (
		rows       []cdxRow
		total      int
		capHit     bool
		resumeKey  string
		emptyPages int
		firstPage  map[string]struct{} // URLs of page 1, for the unpaged fallback
	)

	// emit forwards one row, returning false when the caller must stop: the
	// row cap is reached (the refused row proves there was more) or ctx ended.
	emit := func(row cdxRow) (bool, error) {
		if maxRows > 0 && total >= maxRows {
			capHit = true
			return false, nil
		}
		total++
		// Only mineable rows are retained. The slice exists solely to choose
		// what to read afterwards, so holding an image or a 404 in it costs
		// memory for the length of a network-bound phase and can never earn
		// it back.
		if mineWorthy(row) && len(rows) < mineMaxRows {
			rows = append(rows, row)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case results <- Result{Source: sourceName, URL: row.URL}:
		}
		return true, nil
	}

	for page := 1; ; page++ {
		apiURL := c.indexURL(domain, pageSize, resumeKey, true)
		if page == 1 {
			firstPage = make(map[string]struct{})
		}
		next, n, err := c.readIndexPage(ctx, apiURL, func(row cdxRow) (bool, error) {
			if page == 1 {
				firstPage[row.URL] = struct{}{}
			}
			return emit(row)
		})
		if err != nil {
			if page == 1 || ctx.Err() != nil {
				return rows, err
			}
			// Later pages failing keeps what earlier pages produced: the
			// error still reaches the harvester, and mining still runs.
			return rows, fmt.Errorf("cdx page %d: %w", page, err)
		}
		if capHit || ctx.Err() != nil {
			break
		}

		if next == "" {
			if page == 1 && n >= pageSize {
				zap.L().Debug("Wayback: full first page without a resume key; re-reading unpaged",
					zap.String("domain", domain), zap.Int("page_size", pageSize))
				_, _, err := c.readIndexPage(ctx, c.indexURL(domain, 0, "", false), func(row cdxRow) (bool, error) {
					if _, done := firstPage[row.URL]; done {
						return true, nil
					}
					return emit(row)
				})
				if err != nil && (ctx.Err() != nil || total == 0) {
					return rows, err
				}
				if err != nil {
					return rows, fmt.Errorf("cdx unpaged fallback: %w", err)
				}
			}
			break
		}

		if maxRows > 0 && total >= maxRows {
			capHit = true
			break
		}
		if next == resumeKey {
			zap.L().Debug("Wayback: resume key repeated; stopping", zap.String("domain", domain))
			break
		}
		if n == 0 {
			emptyPages++
			if emptyPages >= cdxMaxEmptyPages {
				zap.L().Debug("Wayback: consecutive empty pages; stopping", zap.String("domain", domain))
				break
			}
		} else {
			emptyPages = 0
		}
		resumeKey = next
		firstPage = nil
	}

	if capHit {
		zap.L().Warn("Wayback: CDX index stopped at max_rows; the harvest for this domain is incomplete",
			zap.String("domain", domain), zap.Int("max_rows", maxRows))
		select {
		case <-ctx.Done():
			return rows, ctx.Err()
		case results <- Result{Source: sourceName, Limit: LimitCDXMaxRows}:
		}
	}
	return rows, ctx.Err()
}

// readIndexPage fetches one index page and hands each row to emit, returning
// the page's resume key ("" when the server sent none) and how many rows it
// delivered. emit returning false stops the read early.
//
// With showResumeKey=true the key is the last line, after a blank line. A
// line is only taken as the key when it follows a blank line, holds no
// whitespace or "://", and nothing but blank lines follows it; otherwise it is
// emitted as an ordinary row (an older server answering with bare URLs).
func (c *waybackClient) readIndexPage(ctx context.Context, apiURL string, emit func(cdxRow) (bool, error)) (string, int, error) {
	resp, err := c.fetchWithRetry(ctx, apiURL)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	var (
		n        int
		sawBlank bool
		pending  string // candidate resume key, not yet known to be last
	)
	handle := func(line string) (bool, error) {
		row := parseCDXLine(line)
		if row.URL == "" {
			return true, nil
		}
		n++
		return emit(row)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", n, err
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			sawBlank = true
			continue
		}
		if pending != "" {
			// More content after the candidate: it was a row after all.
			cont, err := handle(pending)
			pending = ""
			if err != nil || !cont {
				return "", n, err
			}
		}
		if sawBlank && !strings.ContainsAny(line, " \t") && !strings.Contains(line, "://") {
			pending = line
			sawBlank = false
			continue
		}
		sawBlank = false

		cont, err := handle(line)
		if err != nil || !cont {
			return "", n, err
		}
	}

	if err := scanner.Err(); err != nil {
		return "", n, fmt.Errorf("read response: %w", err)
	}
	return pending, n, nil
}

// parseCDXLine splits a plain-text CDX row of
// `original timestamp mimetype statuscode`. Trailing fields may be absent, and a
// row that is nothing but a URL still parses — the field list is a request, not
// a guarantee, and older deployments answer with the URL alone.
//
// Splitting on whitespace is safe because the CDX index stores `original`
// percent-encoded, so a captured URL never contains a literal space.
func parseCDXLine(line string) cdxRow {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return cdxRow{}
	}

	row := cdxRow{URL: fields[0]}
	if len(fields) > 1 {
		row.Timestamp = fields[1]
	}
	if len(fields) > 2 {
		row.MIME = fields[2]
	}
	if len(fields) > 3 {
		row.Status = fields[3]
	}
	return row
}

// replayURL renders the raw-capture replay address for one row. The `id_`
// modifier is what makes this usable: without it the archive rewrites every link
// in the body to point back at itself, which would turn mining into a list of
// web.archive.org URLs.
func (c *waybackClient) replayURL(timestamp, target string) string {
	return fmt.Sprintf("%s/web/%sid_/%s", c.baseURL, timestamp, target)
}

// mine reads a bounded selection of archived bodies and emits the endpoints
// found inside them.
//
// It is skipped entirely when no row carries a timestamp: a replay is addressed
// by timestamp, so without one there is nothing to fetch and the index response
// was not the one this code asked for.
func (c *waybackClient) mine(ctx context.Context, domain string, rows []cdxRow, results chan<- Result, sourceName string) {
	if !slices.ContainsFunc(rows, func(row cdxRow) bool { return row.Timestamp != "" }) {
		return
	}

	e := emitter{ctx: ctx, ch: results, source: sourceName}

	sitemaps := c.mineRobots(domain, rows, e)
	read := c.mineSitemaps(domain, sitemaps, e)

	// Documents already read as sitemaps are skipped: re-fetching one as a
	// generic body would spend a request and one of the scarce body slots to
	// parse it a second time, worse — through the link extractor instead of the
	// sitemap parser.
	targets := selectMineTargets(rows, mineMaxBodies)
	targets = slices.DeleteFunc(targets, func(row cdxRow) bool {
		return read[row.URL] || isRobotsURL(row.URL)
	})
	mineExtracted(domain, targets, func(row cdxRow) []byte {
		return c.mineBody(ctx, row.capture())
	}, e)
}

// mineRobots walks each host's robots.txt history and emits the paths it
// disallowed, returning the sitemaps those files pointed at.
//
// The history is the point. A single current robots.txt is a small file; ten
// years of versions name every admin console, staging path and export endpoint
// the site ever asked crawlers to leave alone.
func (c *waybackClient) mineRobots(domain string, rows []cdxRow, e emitter) []capture {
	hosts := selectRobotsHosts(rows, domain)
	if len(hosts) == 0 {
		return nil
	}

	// The per-host history lookups are themselves round trips against a slow
	// endpoint, so they run concurrently rather than one before the next.
	snapshots := pool.NewWithResults[[]capture]().WithMaxGoroutines(mineConcurrency)
	for _, host := range hosts {
		snapshots.Go(func() []capture { return c.robotsSnapshots(e.ctx, host) })
	}

	found := pool.NewWithResults[[]capture]().WithMaxGoroutines(mineConcurrency)
	for _, snap := range slices.Concat(snapshots.Wait()...) {
		found.Go(func() []capture {
			body := c.mineBody(e.ctx, snap)
			if len(body) == 0 {
				return nil
			}
			base, err := url.Parse(snap.URL)
			if err != nil {
				return nil
			}

			paths, sitemaps := parseRobots(body, base)
			for _, path := range paths {
				if minedURLInScope(path, domain) {
					e.send(path)
				}
			}

			refs := make([]capture, 0, len(sitemaps))
			for _, sitemap := range sitemaps {
				refs = append(refs, capture{URL: sitemap, Timestamp: snap.Timestamp})
			}
			return refs
		})
	}
	return slices.Concat(found.Wait()...)
}

// robotsSnapshots asks the index for the distinct versions of one host's
// robots.txt. collapse=digest is what makes this cheap and worth doing: it
// returns one row per *content* change rather than one per capture, so a file
// fetched daily for a decade comes back as the handful of times it was edited.
func (c *waybackClient) robotsSnapshots(ctx context.Context, host string) []capture {
	target := host + "/robots.txt"
	apiURL := fmt.Sprintf("%s/cdx/search/cdx?url=%s&output=txt&fl=original,timestamp&collapse=digest&filter=statuscode:200&limit=%d",
		c.baseURL, url.QueryEscape(target), mineMaxRobotsSnaps)

	resp, err := c.fetchWithRetry(ctx, apiURL)
	if err != nil {
		zap.L().Debug("Wayback: robots history unavailable", zap.String("host", host), zap.Error(err))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var snapshots []capture
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() && len(snapshots) < mineMaxRobotsSnaps {
		row := parseCDXLine(scanner.Text())
		if row.URL == "" || row.Timestamp == "" {
			continue
		}
		snapshots = append(snapshots, row.capture())
	}
	return snapshots
}

// mineSitemaps follows sitemap documents and emits the URLs they list, returning
// the set it read. A sitemap index points at further sitemaps, so exactly one
// level of nesting is followed before the budget stops it.
func (c *waybackClient) mineSitemaps(domain string, refs []capture, e emitter) map[string]bool {
	read := make(map[string]bool)

	// pass reads every reference it can still afford and returns the nested
	// sitemaps they named. It runs sequentially at the top level and once more
	// for the nested set, which is the whole of the "one level down" rule.
	pass := func(refs []capture) []capture {
		p := pool.NewWithResults[[]capture]().WithMaxGoroutines(mineConcurrency)
		for _, ref := range refs {
			if len(read) >= mineMaxSitemaps {
				break
			}
			if read[ref.URL] {
				continue
			}
			read[ref.URL] = true

			p.Go(func() []capture {
				body := c.mineBody(e.ctx, ref)
				if len(body) == 0 {
					return nil
				}
				base, err := url.Parse(ref.URL)
				if err != nil {
					return nil
				}

				var nested []capture
				for _, entry := range parseSitemap(body, base, domain) {
					if isSitemapURL(entry) {
						nested = append(nested, capture{URL: entry, Timestamp: ref.Timestamp})
						continue
					}
					e.send(entry)
				}
				return nested
			})
		}
		return slices.Concat(p.Wait()...)
	}

	pass(pass(refs))
	return read
}

// mineBody fetches one archived capture, capped at mineMaxBodyBytes. A failure
// is a debug line rather than an error: mining is additive, and losing one
// capture should not cost the index results already emitted.
func (c *waybackClient) mineBody(ctx context.Context, snap capture) []byte {
	if snap.Timestamp == "" || snap.URL == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.replayURL(snap.Timestamp, snap.URL), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		zap.L().Debug("Wayback: replay failed", zap.String("url", snap.URL), zap.Error(err))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	return readCappedBody(resp)
}

func (c *waybackClient) fetchWithRetry(ctx context.Context, apiURL string) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.retryDelay * time.Duration(1<<(attempt-1))
			if delay > c.maxBackoff {
				delay = c.maxBackoff
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			lastErr = &waybackAPIError{
				StatusCode: resp.StatusCode,
				Status:     resp.Status,
				URL:        apiURL,
			}
			continue
		}

		return nil, &waybackAPIError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        apiURL,
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
	}

	return nil, errors.New("max retries exceeded")
}

// WaybackSource collects URLs from the Wayback Machine CDX API.
type WaybackSource struct {
	client *waybackClient
}

// NewWaybackSource creates a new Wayback Machine harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewWaybackSource(proxyURL ...string) *WaybackSource {
	return &WaybackSource{
		client: newWaybackClient(proxyURL...),
	}
}

// setCDXBounds applies the harvest's CDX page size and row cap (cdxTunable).
func (s *WaybackSource) setCDXBounds(pageSize, maxRows int) {
	s.client.pageSize, s.client.maxRows = pageSize, maxRows
	if maxRows == 0 {
		// The harvester resolves "unbounded" to 0; the client reads 0 as
		// "default", so carry unbounded as a negative value.
		s.client.maxRows = -1
	}
}

func (s *WaybackSource) Name() string   { return "wayback" }
func (s *WaybackSource) NeedsKey() bool { return false }

// Run fetches historical URLs for the domain from Wayback Machine.
func (s *WaybackSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if err := s.client.fetch(ctx, domain, results, s.Name()); err != nil {
			select {
			case <-ctx.Done():
			case results <- Result{Source: s.Name(), Error: err}:
			}
		}
	}()

	return results
}
