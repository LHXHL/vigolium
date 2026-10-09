package discovery

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

// initSession prepares engine for discovery.
func (e *Engine) initSession() error {
	if e.config.Target.StartURL == "" {
		return fmt.Errorf("start URL required")
	}

	targetURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return fmt.Errorf("invalid start URL: %w", err)
	}

	// Extract host components as observed names for wordlist
	// e.g., "brand.example.com" → adds "brand", "example"
	// Use trusted frequency since host components are reliable sources.
	hostComponents := ExtractHostComponents(targetURL.Host)
	for _, component := range hostComponents {
		e.AddObservedNameTrusted(component)
	}
	if len(hostComponents) > 0 {
		logger.Debug("Added host components to observed names",
			zap.Strings("components", hostComponents))
	}

	// Always read from sitemap at startup
	logger.Info("Copying existing URLs from sitemap")
	if err := e.copyFromSiteMap(); err != nil {
		logger.Warn("Failed to copy from sitemap", zap.Error(err))
	}

	// Load extractions from database (jstangle requests for task generation)
	if err := e.loadExtractionsFromDB(); err != nil {
		logger.Warn("Failed to load extractions from database", zap.Error(err))
	}

	// Parse the JS that earlier phases (spidering) already collected for routes the
	// discovery crawl would otherwise miss — it only parses JS it fetches itself,
	// so framework bundles the browser captured (e.g. a Salesforce Aura app bundle
	// embedding an /apex/... captcha route) are never mined for endpoints.
	e.extractRoutesFromStoredJS()

	// Re-extract words from stored response bodies if -extract-words is enabled
	if e.wordlistExtractor != nil && e.config.Filenames.WordlistExtraction.Enabled {
		if err := e.extractWordsFromStoredResponses(); err != nil {
			logger.Warn("Failed to extract words from stored responses", zap.Error(err))
		}
	}

	// For a FUZZ template (e.g. "…/%23/../FUZZ"), probe the start URL and pre-warm
	// around the marker's directory rather than the literal "FUZZ" path (see
	// resolveFuzzProbeURL); baseline learning resolves the marker itself (see
	// baselineKeyAndProbe). The FuzzTask still fuzzes the raw marked position.
	probeURL, isFuzzTemplate := resolveFuzzProbeURL(targetURL)
	if isFuzzTemplate {
		logger.Info("FUZZ template detected — probing and baseline-learning around the insertion point",
			zap.String("template", targetURL.String()),
			zap.String("probe_base", probeURL.String()))
	}

	// Probe start URL before scanning
	logger.Info("Probing start URL", zap.String("url", probeURL.String()))
	if err := e.probeStartURL(probeURL); err != nil {
		return fmt.Errorf("start URL probe failed: %w", err)
	}

	// Learn baseline fingerprints for common extensions
	if !e.config.Engine.SkipFingerprintLearning {
		logger.Info("Learning baseline fingerprints for soft 404 detection")
		// Pass the raw target (marker intact): baselineKeyAndProbe resolves it.
		if err := e.learnBaselineFingerprints(targetURL); err != nil {
			logger.Warn("Fingerprint learning failed, continuing without baseline", zap.Error(err))
		}
		// Pre-warm cache for common paths/extensions beyond root to reduce
		// inline learning pauses during the main discovery phase.
		// Fan out at the operator's concurrency; see Cache.PreWarm.
		if e.fpCache != nil {
			e.fpCache.PreWarm(e.ctx, probeURL, e.config.Engine.DiscoveryThreads)
		}
	} else {
		logger.Debug("Skipping fingerprint learning (SkipFingerprintLearning=true)")
	}

	// Confirm which server-side extensions the app actually serves before any
	// extension fuzzing is queued (observed start-URL ext, response fingerprint,
	// active soft-404 differential probe). No-op unless ConfirmRequired.
	e.confirmStartURLExtensions()

	// On a monolith / server-rendered app, sweep common JavaScript bundle names
	// (main.js, admin.js, config.js, …) and feed confirmed hits to jstangle. No-op
	// on JS-shell SPAs (content-hashed, unguessable bundles) and when disabled.
	e.sweepJSBundles()

	logger.Info("Session initialization complete")
	return nil
}

// learnBaselineFingerprints learns 404 signatures for common file extensions at root.
func (e *Engine) learnBaselineFingerprints(baseURL *url.URL) error {
	return e.learnBaselineFingerprintsForDirectory(baseURL)
}

// learnBaselineFingerprintsForDirectory learns 404 signatures for a specific directory.
// Called at startup for root, and when discovering new directories before bruteforce.
func (e *Engine) learnBaselineFingerprintsForDirectory(dirURL *url.URL) error {
	// Cache-key directory and the URL used to probe the baseline (see
	// baselineKeyAndProbe — they differ only for a FUZZ template).
	dirPath, probeBaseURL := e.baselineKeyAndProbe(dirURL)

	// CRITICAL: "" (no extension) MUST be learned FIRST
	var extensions []string
	extensions = append(extensions, "")

	// Add custom extensions if configured
	if e.config.Extensions.TestCustom && len(e.config.Extensions.CustomList) > 0 {
		for _, ext := range e.config.Extensions.CustomList {
			if ext != "" && ext[0] != '.' {
				ext = "." + ext
			}
			extensions = append(extensions, ext)
		}
	}

	logger.Debug("Starting fingerprint learning for directory",
		zap.String("path", dirPath),
		zap.Int("extension_count", len(extensions)))

	var learnedCount atomic.Int32

	// Learn "" (no extension) synchronously first — it MUST complete before others
	if len(extensions) > 0 {
		ext := extensions[0] // always ""
		key := fingerprint.CacheKey{
			Host:      dirURL.Host,
			Path:      dirPath,
			Extension: ext,
		}
		if _, ok := e.fpCache.Get(key); !ok {
			learnURL := *probeBaseURL
			_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
			if err != nil {
				logger.Debug("Failed to learn fingerprint for extension",
					zap.String("path", dirPath),
					zap.String("extension", ext),
					zap.Error(err))
			} else {
				learnedCount.Add(1)
			}
		}
	}

	// Learn remaining extensions in parallel with bounded concurrency
	if len(extensions) > 1 {
		sem := make(chan struct{}, 3)
		var wg sync.WaitGroup

		for _, ext := range extensions[1:] {
			ext := ext // capture loop variable

			key := fingerprint.CacheKey{
				Host:      dirURL.Host,
				Path:      dirPath,
				Extension: ext,
			}

			// Skip if already learned
			if _, ok := e.fpCache.Get(key); ok {
				continue
			}

			wg.Add(1)
			sem <- struct{}{} // acquire semaphore slot
			go func() {
				defer wg.Done()
				defer func() { <-sem }() // release semaphore slot

				learnURL := *probeBaseURL

				_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
				if err != nil {
					logger.Debug("Failed to learn fingerprint for extension",
						zap.String("path", dirPath),
						zap.String("extension", ext),
						zap.Error(err))
					return
				}
				learnedCount.Add(1)

				// Brief delay between requests to avoid overwhelming the server
				time.Sleep(200 * time.Millisecond)
			}()
		}

		wg.Wait()
	}

	logger.Info("Fingerprint learning complete for directory",
		zap.String("path", dirPath),
		zap.Int32("learned", learnedCount.Load()),
		zap.Int("total", len(extensions)))

	return nil
}

// learnBaselineForDirectory learns baseline fingerprint for a discovered directory.
// Only learns "" extension (no extension) to minimize HTTP requests.
// Called before creating recursive bruteforce tasks.
func (e *Engine) learnBaselineForDirectory(dirURL *url.URL) error {
	// Normalize directory path
	dirPath := dirURL.Path
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath[len(dirPath)-1] != '/' {
		dirPath += "/"
	}

	key := fingerprint.CacheKey{
		Host:      dirURL.Host,
		Path:      dirPath,
		Extension: "", // Only learn no-extension baseline
	}

	// Skip if already learned
	if _, ok := e.fpCache.Get(key); ok {
		logger.Debug("Baseline already learned for directory",
			zap.String("path", dirPath))
		return nil
	}

	logger.Info("Learning baseline fingerprint for directory",
		zap.String("path", dirPath))

	// Create URL for learning
	learnURL := *dirURL
	learnURL.Path = dirPath

	_, err := e.fpCache.LearnAndCache(e.ctx, key, &learnURL)
	if err != nil {
		return fmt.Errorf("learn baseline for %s: %w", dirPath, err)
	}

	return nil
}

// probeStartURL validates the start URL with an HTTP GET request.
func (e *Engine) probeStartURL(targetURL *url.URL) error {
	req, err := pkghttp.NewRequest(targetURL.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return fmt.Errorf("failed to create probe request: %w", err)
	}

	logger.Debug("Sending probe request", zap.String("url", targetURL.String()))
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return fmt.Errorf("probe request failed: %w", err)
	}
	defer rc.Close()

	resp := rc.Response()
	body := rc.BodyBytes()

	// Snapshot response headers for fingerprint-based extension confirmation, and
	// record the landing page's shape (HTML? JS-shell SPA?) for the JS-bundle sweep.
	if resp != nil {
		e.startURLHeader = resp.Header.Clone()
		e.startURLStatus = resp.StatusCode
		// A 3xx redirect target (Location) or a 200-served login form both mean the
		// root is an auth gate, not the app — used to gate fingerprint confirmation.
		e.startURLIsLogin = authsig.LooksLikeLoginURL(targetURL) ||
			authsig.BodyLooksLikeLogin(body)
		if loc := resp.Header.Get("Location"); loc != "" {
			if locURL, err := targetURL.Parse(loc); err == nil && authsig.LooksLikeLoginURL(locURL) {
				e.startURLIsLogin = true
			}
		}
		e.captureStartURLAppShape(targetURL.Path, resp.Header.Get("Content-Type"), body)
	}

	found, err := e.analyzer.Analyze(e.ctx, req, rc)
	if err != nil {
		return fmt.Errorf("response analysis failed: %w", err)
	}

	logger.Info("Probe request completed",
		zap.String("url", targetURL.String()),
		zap.Int("status_code", resp.StatusCode),
		zap.Bool("found", found),
		zap.Int("body_size", len(body)))

	// Extract links and names from probe response
	logger.Debug("Extracting links from probe response")
	e.extractLinks(targetURL, rc, 0)

	return nil
}

// generateInitialTasks creates first wave of discovery tasks.
func (e *Engine) generateInitialTasks() {
	logger.Info("Generating initial discovery tasks")

	// Parse StartURL and strip query params for wordlist/observed tasks.
	// Query params should NOT be included in bruteforce base URLs.
	parsedStart, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		logger.Error("Failed to parse start URL", zap.Error(err))
		return
	}
	// For a FUZZ template, the observed/wordlist/malformed bruteforce builds off
	// the marker's directory (through any bypass prefix), not the literal "…/FUZZ/"
	// path. The FuzzTask below still fuzzes the raw marked position. No-op otherwise.
	parsedStart, _ = resolveFuzzProbeURL(parsedStart)
	baseURLNoQuery := &url.URL{
		Scheme:  parsedStart.Scheme,
		Host:    parsedStart.Host,
		Path:    parsedStart.Path,
		RawPath: parsedStart.RawPath,
	}
	baseURL := []byte(baseURLNoQuery.String())
	depth := uint16(0)

	tasks, err := e.factory.CreateInitialTasks(baseURL, depth)
	if err != nil {
		logger.Error("Failed to create initial tasks", zap.Error(err))
		return
	}

	logger.Debug("Enqueuing initial tasks", zap.Int("count", len(tasks)))
	e.addTasks(tasks)

	// Create observed name tasks
	// Note: CreateObservedNameTasks internally extracts scheme://host and path from baseURL
	observedTasks := e.factory.CreateObservedNameTasks(baseURL, depth, e.observedNames, e.observedExtensions)
	logger.Debug("Enqueuing observed name tasks", zap.Int("count", len(observedTasks)))
	e.addTasks(observedTasks)

	// Create observed directory tasks
	// Extract scheme://host and path for the new API
	schemeHost := extractSchemeHost(string(baseURL))
	dirPath := extractPathFromURL(string(baseURL))
	observedDirTasks := e.factory.CreateObservedDirectoryTasks([]byte(schemeHost), dirPath, depth, e.observedNames)
	logger.Debug("Enqueuing observed directory tasks", zap.Int("count", len(observedDirTasks)))
	e.addTasks(observedDirTasks)

	// Create observed path tasks (segments already in observedNames, handled by existing tasks)
	var observedPathTasks []Task
	if e.config.Filenames.UseObservedPaths {
		observedPathTasks = e.factory.CreateObservedPathTasks(baseURL, depth, e.observedPaths)
		logger.Debug("Enqueuing observed path tasks", zap.Int("count", len(observedPathTasks)))
		e.addTasks(observedPathTasks)
	}

	// Create JS extracted request task for root URL
	if e.jstangleService != nil {
		targetURL, err := url.Parse(e.config.Target.StartURL)
		if err == nil {
			jsExtTask := e.factory.CreateJSExtractedRequestTask(
				targetURL,
				e.GetExtractedRequests,
				depth,
				e.PendingRequestTemplates,
			)
			if jsExtTask != nil {
				e.AddTask(jsExtTask)
				logger.Debug("Added JS extracted request task for root URL")
			}
		}
	}

	// Create fuzz wordlist task (Priority 12: runs after all other wordlists)
	if e.config.Filenames.Wordlists.HasFuzzWordlist() {
		// Build URL template: use StartURL as-is if it contains FUZZ,
		// otherwise auto-append /FUZZ to the URL.
		fuzzTemplate := e.config.Target.StartURL
		if !strings.Contains(fuzzTemplate, fuzzMarker) {
			fuzzTemplate = strings.TrimRight(fuzzTemplate, "/") + "/" + fuzzMarker
		}

		// Words are deduplicated across the (possibly several, possibly
		// huge) fuzz wordlists on disk, not in memory.
		var seen payload.SeenSet
		if e.fuzzWordsSeen == nil && e.dedupBasePath != "" {
			ds, dsErr := newDiskSet(e.dedupBasePath, "fuzz-words")
			if dsErr != nil {
				logger.Warn("Fuzz wordlist dedup store unavailable; deduplicating in memory", zap.Error(dsErr))
			} else {
				e.fuzzWordsSeen = ds
			}
		}
		if e.fuzzWordsSeen != nil {
			seen = e.fuzzWordsSeen
		}

		fuzzTask, err := e.factory.CreateFuzzTask(
			fuzzTemplate,
			e.config.Filenames.Wordlists.FuzzWordlists(),
			seen,
			depth,
		)
		if err != nil {
			logger.Error("Failed to create fuzz task", zap.Error(err))
		} else {
			e.AddTask(fuzzTask)
			logger.Debug("Added fuzz wordlist task",
				zap.String("template", fuzzTemplate))
		}
	}

	// Malformed path probe (Priority 10: runs against start URL)
	if e.config.Filenames.EnableMalformedPathProbe {
		probeTask := e.factory.CreateMalformedPathProbeTask([]byte(schemeHost), []byte(dirPath), depth)
		if probeTask != nil {
			e.AddTask(probeTask)
			logger.Debug("Added malformed path probe task",
				zap.String("path", dirPath))
		}
	}

	logger.Info("Initial task generation complete",
		zap.Int("total_tasks", len(tasks)+len(observedTasks)+len(observedDirTasks)+len(observedPathTasks)))
}

// copyFromSiteMap populates observed collections from existing sitemap.
func (e *Engine) copyFromSiteMap() error {
	if e.storage == nil {
		return nil
	}

	// Load from observed table (with frequencies preserved from previous runs)
	if err := e.loadObservedFromDB(); err != nil {
		logger.Warn("Failed to load observed data from DB", zap.Error(err))
		// Continue - not fatal, we can still extract from sitemap
	}

	// Walk existing nodes for additional extraction
	return extractFilenamesFromSitemap(e)
}

// loadObservedFromDB loads previously stored observed data with frequencies.
func (e *Engine) loadObservedFromDB() error {
	repo := e.storage.Observed()
	if repo == nil {
		return nil
	}

	hostname := e.storage.Hostname()
	if hostname == "" {
		return nil
	}

	items, err := repo.GetByHostname(hostname)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	var namesCount, extsCount, pathsCount, filesCount int

	for _, item := range items {
		switch storage.ObservedType(item.Type) {
		case storage.ObservedTypeName:
			// Sanitize name to clean legacy data that may contain query params
			name := sanitizeObservedName(item.Value)
			if name != "" {
				e.observedNames.AddWithFrequency([]byte(name), item.Frequency)
				namesCount++
			}
		case storage.ObservedTypeExtension:
			e.observedExtensions.AddWithFrequency([]byte(item.Value), item.Frequency)
			// Also mark as seen in seenExtensions to prevent duplicate task generation
			if e.seenExtensions != nil {
				e.seenExtensions.IsSeen(item.Value)
			}
			extsCount++
		case storage.ObservedTypePath:
			e.observedPaths.AddWithFrequency([]byte(item.Value), item.Frequency)
			pathsCount++
		case storage.ObservedTypeFile:
			e.observedFiles.AddWithFrequency([]byte(item.Value), item.Frequency)
			filesCount++
		}
	}

	logger.Info("Loaded observed data from database",
		zap.Int("names", namesCount),
		zap.Int("extensions", extsCount),
		zap.Int("paths", pathsCount),
		zap.Int("files", filesCount))

	return nil
}

// extractWordsFromStoredResponses re-extracts words from all stored response bodies.
func (e *Engine) extractWordsFromStoredResponses() error {
	if e.storage == nil || e.wordlistExtractor == nil {
		return nil
	}

	logger.Info("Re-extracting words from stored response bodies")

	count := extractWordsFromResponses(e)

	logger.Info("Word extraction from stored responses complete",
		zap.Int("words_extracted", count))

	return nil
}

// fetchRobotsTxt fetches and parses robots.txt to discover initial URLs, then
// runs the sitemap source over the sitemaps it names (or the default sitemap
// paths when it names none). Non-fatal: failures are logged and discovery goes on.
func (e *Engine) fetchRobotsTxt(baseURL *url.URL) {
	named := e.loadRobotsTxt(baseURL)
	e.fetchSitemaps(baseURL, named)
}

// loadRobotsTxt fetches robots.txt, feeds it through the spider coordinator and
// returns the Sitemap: URLs it declares (nil when it is missing or names none).
func (e *Engine) loadRobotsTxt(baseURL *url.URL) []*url.URL {
	robotsURL := *baseURL
	robotsURL.Path = "/robots.txt"
	robotsURL.RawPath = ""
	robotsURL.RawQuery = ""
	robotsURL.Fragment = ""

	req, err := pkghttp.NewRequest(robotsURL.String()).
		Headers(e.config.Engine.CustomHeaders).
		Build()
	if err != nil {
		logger.Debug("Failed to build robots.txt request", zap.Error(err))
		return nil
	}

	logger.Debug("Fetching robots.txt", zap.String("url", robotsURL.String()))
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		logger.Debug("robots.txt fetch failed", zap.Error(err))
		return nil
	}
	defer rc.Close()

	resp := rc.Response()

	// Skip non-success responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Debug("robots.txt returned non-success status",
			zap.Int("status", resp.StatusCode))
		return nil
	}

	// With the sitemap source on, the declared sitemaps are fetched and parsed by
	// fetchSitemaps. Mark them seen first so the robots link batch below does not
	// also spider them as opaque files, whose inline-URL scan would queue every
	// <loc> unsampled.
	var named []*url.URL
	if e.config.Sitemap.Enabled && e.spiderResolver != nil {
		named = spider.NewRobotsTxtParser(e.spiderResolver).SitemapURLs(&robotsURL, rc.BodyBytes())
		if e.seenDiscoveredURLs != nil {
			for _, u := range named {
				e.seenDiscoveredURLs.IsSeen(dedup.NormalizeURL(u.String()))
			}
		}
	}

	// Extract links using spider coordinator (runs RobotsTxtParser)
	e.extractLinks(&robotsURL, rc, 0)
	logger.Info("robots.txt parsed", zap.String("url", robotsURL.String()),
		zap.Int("sitemaps", len(named)))
	return named
}

// defaultSitemapPaths are probed when robots.txt names no sitemap.
var defaultSitemapPaths = []string{"/sitemap.xml", "/sitemap_index.xml"}

// maxSitemapDocuments bounds the sitemap documents fetched per target: the
// robots-named (or default) roots plus the index children they lead to.
const maxSitemapDocuments = 32

// sitemapOutcome summarizes one fetchSitemaps run (logged; returned for tests).
type sitemapOutcome struct {
	Documents  int        // sitemap documents fetched and parsed
	Locs       int        // in-scope page locs read (all feed the observed-path wordlist)
	OutOfScope int        // page locs dropped by the spider scope
	Sampled    []*url.URL // locs queued as spider links
	Capped     int        // locs or documents dropped by a budget (sitemap_cap)
}

// fetchSitemaps is the sitemap source. It fetches the sitemaps robots.txt
// named — or /sitemap.xml and /sitemap_index.xml when it named none — follows
// <sitemapindex> children (depth <= 2, <= 16 per index, <= 32 documents in
// all), and streams every <loc> (gzip and text sitemaps included, see
// spider.ParseSitemap). Every in-scope loc feeds the observed-path wordlist;
// a path-shape sample of them (per_shape per shape, max_urls in all) becomes
// spider links, so each sampled page is fetched and recorded. Anything a
// budget drops is counted in SitemapCapped.
func (e *Engine) fetchSitemaps(baseURL *url.URL, named []*url.URL) sitemapOutcome {
	var out sitemapOutcome
	cfg := e.config.Sitemap
	if !cfg.Enabled || baseURL == nil || e.spiderResolver == nil {
		return out
	}

	type sitemapDoc struct {
		u     *url.URL
		depth int
	}
	var queue []sitemapDoc
	if len(named) > 0 {
		for _, u := range named {
			queue = append(queue, sitemapDoc{u: u, depth: 1})
		}
	} else {
		for _, p := range defaultSitemapPaths {
			u := &url.URL{Scheme: baseURL.Scheme, Host: baseURL.Host, Path: p}
			queue = append(queue, sitemapDoc{u: u, depth: 1})
		}
	}

	extractor := spider.NewSitemapExtractor(e.spiderResolver)
	sampler := spider.NewSitemapSampler(cfg.EffectivePerShape(), cfg.EffectiveMaxURLs())
	fetched := make(map[string]struct{})

	for len(queue) > 0 && e.ctx.Err() == nil {
		doc := queue[0]
		queue = queue[1:]

		key := dedup.NormalizeURL(doc.u.String())
		if _, dup := fetched[key]; dup {
			continue
		}
		if !e.spiderScope.IsInScope(doc.u) {
			logger.Debug("Skipping out-of-scope sitemap", zap.String("url", doc.u.String()))
			continue
		}
		if out.Documents >= maxSitemapDocuments {
			out.Capped++
			continue
		}
		fetched[key] = struct{}{}
		out.Documents++

		children := 0
		kind, err := e.fetchSitemapDocument(extractor, doc.u, func(link *spider.DiscoveredLink) {
			if link.ResourceType == spider.ResourceSitemap {
				if !cfg.FollowIndex {
					return
				}
				if doc.depth >= spider.SitemapMaxIndexDepth || children >= spider.SitemapMaxIndexChildren {
					out.Capped++
					return
				}
				children++
				queue = append(queue, sitemapDoc{u: link.URL, depth: doc.depth + 1})
				return
			}
			if !e.spiderScope.IsInScope(link.URL) {
				out.OutOfScope++
				return
			}
			out.Locs++
			e.AddObservedPathTrusted(link.URL.Path)
			sampler.Add(link.URL)
		})
		switch {
		case spider.IsSitemapLimit(err):
			out.Capped++
			logger.Info("Sitemap cut short by a size or entry cap",
				zap.String("url", doc.u.String()), zap.Error(err))
		case err != nil:
			logger.Debug("Sitemap parse stopped", zap.String("url", doc.u.String()), zap.Error(err))
		}
		if kind != spider.SitemapUnknown {
			logger.Debug("Sitemap parsed", zap.String("url", doc.u.String()),
				zap.String("kind", kind.String()), zap.Int("depth", doc.depth))
		}
	}

	out.Sampled = sampler.Sample()
	out.Capped += sampler.Capped()
	if out.Capped > 0 {
		e.sitemapCapped.Add(int64(out.Capped))
	}

	if len(out.Sampled) > 0 {
		links := make([]*spider.DiscoveredLink, 0, len(out.Sampled))
		for _, u := range out.Sampled {
			links = append(links, &spider.DiscoveredLink{
				SourceType:   spider.SourceSitemap,
				URL:          u,
				RawURL:       u.String(),
				ResourceType: spider.ResourceHTML,
				StartPos:     -1,
				EndPos:       -1,
				Element:      "sitemap",
			})
		}
		for _, batch := range e.collectValidatedLinks(links, 0) {
			e.createSpiderBatchTask(batch)
		}
	}

	if out.Documents > 0 {
		logger.Info("Sitemaps processed",
			zap.Int("documents", out.Documents),
			zap.Int("locs", out.Locs),
			zap.Int("shapes", sampler.Shapes()),
			zap.Int("sampled", len(out.Sampled)),
			zap.Int("capped", out.Capped))
	}
	return out
}

// fetchSitemapDocument GETs one sitemap and streams its entries to callback.
// A non-2xx answer (the default probes usually 404) yields SitemapUnknown and
// no error.
func (e *Engine) fetchSitemapDocument(extractor *spider.SitemapExtractor, docURL *url.URL, callback spider.LinkCallback) (spider.SitemapKind, error) {
	req, err := pkghttp.NewRequest(docURL.String()).
		Headers(e.config.Engine.CustomHeaders).
		Build()
	if err != nil {
		return spider.SitemapUnknown, err
	}
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return spider.SitemapUnknown, err
	}
	defer rc.Close()

	if status := rc.Response().StatusCode; status < 200 || status >= 300 {
		return spider.SitemapUnknown, nil
	}
	return extractor.ExtractDeclared(e.ctx, docURL, rc.BodyBytes(), callback)
}

// SitemapCapped returns how many sitemap locs or documents this engine dropped
// because a sitemap budget (max_urls, the per-document entry/size caps, the
// index child/depth caps) was reached. Above zero is the sitemap_cap limit.
func (e *Engine) SitemapCapped() int {
	return int(e.sitemapCapped.Load())
}

// fuzzMarker is the placeholder the discovery fuzzer substitutes with each
// wordlist word (see FuzzTask). Start-URL probing, soft-404 baseline learning and
// the observed/wordlist/malformed task bases must resolve it — not treat it as a
// literal path segment — so their requests land where the real fuzz requests do.
const fuzzMarker = "FUZZ"

// fuzzBaselineToken is the fixed, never-existent segment the marker is replaced
// with when sampling the soft-404 baseline for a FUZZ template.
const fuzzBaselineToken = "vigoliumbaseline"

// resolveFuzzProbeURL returns the URL that start-URL probing and soft-404 baseline
// learning should use for a FUZZ template. When the marker is in the path, the URL
// is reduced to the directory that CONTAINS the marker (preserving any
// path-normalization bypass prefix like "/%23/../" verbatim on the wire) so
// baselines are learned AROUND the insertion point and keyed to the same directory
// as the real fuzzed hits. When the marker is only in the query, the path is the
// real endpoint and only the query is dropped. The second return is true when the
// URL carried a marker; otherwise a copy is returned unchanged.
func resolveFuzzProbeURL(startURL *url.URL) (*url.URL, bool) {
	u := *startURL
	esc := u.EscapedPath()
	if i := strings.Index(esc, fuzzMarker); i >= 0 {
		dir := "/"
		if cut := strings.LastIndex(esc[:i], "/"); cut >= 0 {
			dir = esc[:cut+1]
		}
		fingerprint.SetWirePath(&u, dir)
		u.RawQuery = ""
		u.Fragment = ""
		return &u, true
	}
	if strings.Contains(u.RawQuery, fuzzMarker) {
		u.RawQuery = ""
		return &u, true
	}
	return &u, false
}

// baselineKeyAndProbe returns the cache-key directory path and the URL used to
// probe the soft-404 baseline for dirURL. For a normal directory both describe
// the same directory. For a FUZZ template the marker is substituted (see below) so
// the baseline is sampled at the real fuzzed hits' routing and keyed to their
// directory.
func (e *Engine) baselineKeyAndProbe(dirURL *url.URL) (keyDirPath string, probeBaseURL *url.URL) {
	esc := dirURL.EscapedPath()
	if strings.Contains(esc, fuzzMarker) {
		// Substitute the marker with a fixed non-existent token, preserving the rest
		// of the wire path (including any "/%23/../" bypass prefix). Both the probe
		// AND the key are derived from this substituted URL: the learner mutates the
		// token to generate never-existent siblings at the same routing as the real
		// hits, and the key is computed by the SAME ExtractCacheKey the hits use —
		// whose directory is path.Dir-cleaned, so a bypass prefix collapses (e.g. to
		// "/"). Keeps the fingerprint layer marker-agnostic.
		rep := *dirURL
		fingerprint.SetWirePath(&rep, strings.ReplaceAll(esc, fuzzMarker, fuzzBaselineToken))
		return fingerprint.ExtractCacheKey(&rep).Path, &rep
	}

	// Normal directory: key and probe both describe dirURL with a trailing slash.
	dirPath := dirURL.Path
	if dirPath == "" {
		dirPath = "/"
	}
	if dirPath[len(dirPath)-1] != '/' {
		dirPath += "/"
	}
	probe := *dirURL
	probe.Path = dirPath
	return dirPath, &probe
}
