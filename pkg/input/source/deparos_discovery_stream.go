package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// Streaming one target's referenced class while its crawl runs.
//
// The siteMap is read through a cursor (StreamResultsSince), so the records a
// target collects can be handed on in batches instead of only once the engine
// stops. Two classes are treated differently:
//
//   - The referenced class (JSTangle, form and API-spec records; see
//     classifyDiscoverySource) is exempt from every fuzz-noise pass, so nothing
//     later in the crawl can change whether one of them is kept. A flusher
//     persists and emits it every flush interval or every flushNodes new nodes,
//     which bounds what a kill or abort loses to one interval and lets
//     assessment start on the most valuable records while the crawl goes on.
//   - The fuzz class (crawlRecordSource) stays end-of-target. Hard dedup keeps
//     the shorter path and can evict a record already read, and the cluster cap
//     ranks records shortest-path-first, so neither decision is final until
//     every node is in. The same cursor reads it, so the in-memory dedup state is
//     carried across reads rather than rebuilt.

const (
	// defaultDiscoveryFlushInterval is how often a running target's referenced
	// class is persisted and emitted when nothing configures it.
	defaultDiscoveryFlushInterval = 15 * time.Second
	// defaultDiscoveryFlushNodes flushes early once this many nodes landed since
	// the last flush, so a fast crawl does not sit on a large batch.
	defaultDiscoveryFlushNodes = 500
	// maxDiscoveryFlushPoll bounds how often the flusher checks the node count.
	// The check is a primary-key lookup, so a second is cheap and still turns
	// the node threshold into a prompt flush.
	maxDiscoveryFlushPoll = time.Second
)

// flushSettings resolves the streaming knobs: the interval, the node threshold,
// and whether in-crawl flushing runs at all (a negative interval turns it off,
// leaving everything to the end of the target as before).
func (c DeparosDiscoveryConfig) flushSettings() (interval time.Duration, nodes int, enabled bool) {
	interval = c.FlushInterval
	switch {
	case interval < 0:
		return 0, 0, false
	case interval == 0:
		interval = defaultDiscoveryFlushInterval
	}
	nodes = c.FlushNodes
	if nodes <= 0 {
		nodes = defaultDiscoveryFlushNodes
	}
	return interval, nodes, true
}

// targetEngineFacts is what the end of a target reads from its engine.
type targetEngineFacts interface {
	RequestTemplateOutcomes() []discovery.TemplateOutcome
	JSFactBundles() []discovery.JSFactBundle
	SitemapCapped() int
}

// targetCollector is one target's read state across flushes: the siteMap
// cursor, the fuzz class with its exact-dedup map, the node index the JS
// template plan needs, and the import accumulator every flush and the final
// import share (so uuidByURL and the emit latch span the whole target).
type targetCollector struct {
	d       *DeparosDiscoverySource
	target  string
	siteMap *deparosstorage.SiteMap

	// mu serializes reads and imports between the flusher and the final drain.
	mu sync.Mutex
	// cursor is the siteMap node id read up to. Atomic so the flusher's poll can
	// compare it with LatestNodeID without waiting for a flush in progress.
	cursor atomic.Int64

	stats    DiscoveryStats // TotalDiscovered, AllCodes, DedupedCodes
	fuzz     []collectedRecord
	dedupMap map[hardDedupKey]int // key -> index in fuzz
	nodes    *nodeIndex

	// referenced records read but not yet imported, and how many there were in
	// total and how many an in-crawl flush already imported.
	pendingRefs  []collectedRecord
	refTotal     int
	refStreamed  int
	specStreamed int

	// batch holds the records with a response read by the current collect, the
	// input to API-spec extraction; specSeen dedups spec bodies across batches.
	batch    []*httpmsg.HttpRequestResponse
	specSeen map[string]struct{}

	acc     *importAccum
	flushes int
}

func newTargetCollector(d *DeparosDiscoverySource, target string, siteMap *deparosstorage.SiteMap) *targetCollector {
	return &targetCollector{
		d:        d,
		target:   target,
		siteMap:  siteMap,
		dedupMap: make(map[hardDedupKey]int),
		nodes:    newNodeIndex(64),
		specSeen: make(map[string]struct{}),
		acc:      newImportAccum(64),
	}
}

// collect reads every node stored since the cursor. Callers hold c.mu.
func (c *targetCollector) collect() error {
	c.batch = c.batch[:0]
	next, err := c.siteMap.StreamResultsSince(c.cursor.Load(), c.addNode)
	c.cursor.Store(next)
	return err
}

// addNode classifies one siteMap node into the referenced or fuzz class,
// applying the fuzz class's exact dedup.
func (c *targetCollector) addNode(node *deparosstorage.DiscoveredNode) error {
	// abort, not done: this reads the local temp SQLite file the requests
	// already paid for. The consumer going away is no reason to throw it out —
	// those records can still be persisted.
	select {
	case <-c.d.abort:
		return fmt.Errorf("source aborted")
	default:
	}

	nodeURL := node.URL()
	if nodeURL == nil {
		return nil
	}

	// Preserve the discovered method/headers/body. Deparos storage persists
	// these (req_method/req_headers/req_body) for form POSTs and JS-derived
	// API calls; importing them as a bodyless GET would silently drop that
	// API/form coverage from dynamic assessment.
	method := "GET"
	var reqHeaders map[string]string
	var reqBody []byte
	if req := node.Request(); req != nil {
		if req.Method != "" {
			method = strings.ToUpper(req.Method)
		}
		reqHeaders = req.Headers
		reqBody = req.Body
	}

	rr, err := httpmsg.GetRawRequestFromURLWithMethod(nodeURL.String(), method, reqHeaders, reqBody)
	if err != nil {
		return nil // skip URLs we can't parse
	}
	c.nodes.add(method, nodeURL.String(), rr.Target())

	// Classify provenance: code-referenced classes (JSTangle/form) carry a
	// distinct source label and bypass the fuzz-noise cleanup entirely.
	recSource := crawlRecordSource
	if meta := node.Metadata(); meta != nil {
		recSource = classifyDiscoverySource(meta.FoundBy)
	}
	referenced := recSource != crawlRecordSource

	resp := node.Response()
	hasResp := resp != nil && resp.StatusCode > 0

	rec := collectedRecord{rr: rr, path: nodeURL.Path, host: nodeURL.Hostname(), method: method, source: recSource}

	if hasResp {
		rawResp := httpmsg.BuildRawResponse(resp.StatusCode, resp.Headers, string(resp.Body))
		// DurationMs survives the round trip through the deparos store, so a
		// discovery record carries the real round-trip time rather than the
		// zero every native-scan record used to have. Zero here still means
		// "not measured" and is passed through as such.
		httpResp := httpmsg.NewHttpResponseWithDuration(rawResp,
			time.Duration(resp.DurationMs)*time.Millisecond)
		rr = rr.WithResponse(httpResp)
		rec.rr = rr
		rec.status = resp.StatusCode
		rec.ctype = resp.MIMEType
		rec.size = int64(len(resp.Body))
		rec.words = resp.Words
		if rec.words == 0 && len(resp.Body) > 0 {
			rec.words = int64(len(strings.Fields(string(resp.Body))))
		}
		c.batch = append(c.batch, rr)
	}

	c.stats.TotalDiscovered++
	if hasResp {
		c.stats.AllCodes[statusCodeBucket(resp.StatusCode)]++
	}

	// Code-referenced records (JSTangle/form) skip the fuzz-noise hard dedup:
	// they are high-precision application endpoints that must all survive, even
	// when two distinct routes return byte-identical bodies (two APIs both
	// answering `{}`). They are final as soon as they are read, which is what
	// lets a flush hand them on mid-crawl.
	if referenced {
		c.pendingRefs = append(c.pendingRefs, rec)
		c.refTotal++
		return nil
	}
	// No response, no body to hash: always kept.
	if !hasResp {
		c.fuzz = append(c.fuzz, rec)
		return nil
	}

	// Exact dedup keyed on the response BODY hash (not the full raw
	// response): volatile headers like Date/Set-Cookie and Go's randomized
	// header-map ordering otherwise make every raw response hash unique,
	// defeating the dedup. Body-only collapses byte-identical bodies served
	// across different paths regardless of header noise.
	h := sha256.Sum256(resp.Body)
	key := hardDedupKey{
		hostname: rec.host,
		method:   rec.method,
		status:   resp.StatusCode,
		length:   rec.size,
		respHash: hex.EncodeToString(h[:]),
	}

	if existingIdx, exists := c.dedupMap[key]; exists {
		c.stats.DedupedCodes[statusCodeBucket(resp.StatusCode)]++
		// Keep the shorter path.
		if len(rec.path) < len(c.fuzz[existingIdx].path) {
			c.fuzz[existingIdx] = collectedRecord{} // tombstone
			c.dedupMap[key] = len(c.fuzz)
			c.fuzz = append(c.fuzz, rec)
		}
		return nil
	}
	c.dedupMap[key] = len(c.fuzz)
	c.fuzz = append(c.fuzz, rec)
	return nil
}

// batchSpecEndpoints extracts API-spec endpoints from the current batch,
// skipping spec documents an earlier batch already parsed.
func (c *targetCollector) batchSpecEndpoints() []*httpmsg.HttpRequestResponse {
	return extractSpecEndpointsSeen(c.batch, c.specSeen)
}

// flush reads what landed since the last read and persists + emits its
// referenced class and API-spec endpoints. The fuzz class stays in memory for
// finish. A flush that finds nothing referenced writes nothing.
func (c *targetCollector) flush(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.collect(); err != nil {
		return err
	}
	refs := c.pendingRefs
	c.pendingRefs = nil
	specs := c.batchSpecEndpoints()
	if len(refs) == 0 && len(specs) == 0 {
		return nil
	}

	importCtx, release := importContext(ctx, c.d.cfg.DrainTimeout)
	defer release()

	order, bySource, _ := groupCollectedBySource(refs)
	for _, label := range order {
		if err := c.d.importGroup(importCtx, c.acc, bySource[label], label); err != nil {
			return err
		}
	}
	if err := c.d.importGroup(importCtx, c.acc, specs, specRecordSource); err != nil {
		return err
	}
	c.refStreamed += len(refs)
	c.specStreamed += len(specs)
	c.flushes++
	zap.L().Debug("Streamed referenced discovery records",
		zap.String("target", c.target),
		zap.Int("referenced", len(refs)),
		zap.Int("spec_endpoints", len(specs)),
		zap.Int64("cursor", c.cursor.Load()))
	return nil
}

// startFlusher runs flush on a timer while the crawl is running and returns the
// function that stops it and waits for it to exit. With streaming disabled it
// returns a no-op.
func (c *targetCollector) startFlusher(ctx context.Context) (stop func()) {
	interval, nodes, enabled := c.d.cfg.flushSettings()
	if !enabled {
		return func() {}
	}
	poll := min(interval, maxDiscoveryFlushPoll)
	quit := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		c.runFlusher(ctx, quit, interval, nodes, poll)
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(quit) })
		<-exited
	}
}

func (c *targetCollector) runFlusher(ctx context.Context, quit <-chan struct{}, interval time.Duration, nodes int, poll time.Duration) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-quit:
			return
		case <-c.d.abort:
			return
		case <-ticker.C:
		}
		due := time.Since(last) >= interval
		if !due && c.siteMap.LatestNodeID()-c.cursor.Load() < int64(nodes) {
			continue
		}
		last = time.Now()
		if err := c.flush(ctx); err != nil {
			// The final drain re-reads from the cursor and reports what it
			// cannot import; a failed flush only delays these records.
			zap.L().Debug("Discovery flush failed; leaving the rest to the end of the target",
				zap.String("target", c.target), zap.Error(err))
		}
	}
}

// finish is the end of the target: read the rest of the siteMap, cap the fuzz
// class, plan the JS templates, and import everything not already streamed.
func (c *targetCollector) finish(ctx context.Context, engine targetEngineFacts, timedOut bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	d := c.d
	localStats := c.stats
	if timedOut {
		localStats.TargetsTimedOut++
	}
	// Whatever was imported, by a flush or below, is counted even when the rest
	// of the target fails.
	defer func() {
		d.mu.Lock()
		d.stats.Imported += c.acc.imported
		d.stats.ImportFailed += c.acc.failed
		d.mu.Unlock()
	}()

	if err := c.collect(); err != nil {
		return err
	}
	localStats.TotalDiscovered = c.stats.TotalDiscovered
	localStats.AllCodes = c.stats.AllCodes
	localStats.DedupedCodes = c.stats.DedupedCodes

	// JS-derived request templates and non-request facts, read before the
	// siteMap closes: everything that did not become a node lives only here.
	var fallbackURL *url.URL
	if parsed, perr := url.Parse(c.target); perr == nil {
		fallbackURL = parsed
	}
	jsPlan := planJSTemplates(engine.RequestTemplateOutcomes(), c.nodes, fallbackURL, d.cfg.JSTemplatePersist)
	jsPlan.bundles = engine.JSFactBundles()

	// Drop exact-dedup tombstones: only the fuzz/crawl class is subject to the
	// flood-control cap below — code-referenced records must all survive.
	fuzz := make([]collectedRecord, 0, len(c.fuzz))
	for _, rec := range c.fuzz {
		if rec.rr != nil {
			fuzz = append(fuzz, rec)
		}
	}
	localStats.HardDedupRemoved = localStats.TotalDiscovered - (len(fuzz) + c.refTotal)

	// Near-identical cluster cap: backstop for catch-all/SPA targets that the
	// exact hash and the engine's soft-404 detection can't collapse because each
	// response differs by a few bytes/words. Keeps at most clusterCap records per
	// (host, status, content-type, ~size, ~words) cluster.
	clusterCap := d.cfg.resolveClusterCap()
	localStats.ClusterCap = clusterCap
	if clusterCap > 0 {
		var capped int
		var cappedCodes [5]int
		fuzz, capped, cappedCodes = capNearIdenticalClusters(fuzz, clusterCap)
		localStats.FuzzyCappedRemoved = capped
		localStats.CappedCodes = cappedCodes
	}

	// Regroup the survivors by source label. The fuzz class keeps the
	// crawlRecordSource ("deparos") label so the post-discovery dedup/status
	// passes apply to it; code-referenced classes not yet streamed carry their
	// own label and are left alone (see classifyDiscoverySource).
	kept := make([]collectedRecord, 0, len(fuzz)+len(c.pendingRefs))
	kept = append(kept, fuzz...)
	kept = append(kept, c.pendingRefs...)
	c.pendingRefs = nil
	sourceOrder, bySource, _ := groupCollectedBySource(kept)

	// Parse API specs (OpenAPI/Swagger/Postman/WSDL) found among the responses
	// read since the last flush and queue their documented endpoints. They are
	// persisted separately under specRecordSource so the deparos dedup/status
	// passes don't drop or collapse them once each carries a real (often
	// uniform 401) baseline response.
	specEndpoints := c.batchSpecEndpoints()
	if total := len(specEndpoints) + c.specStreamed; total > 0 {
		terminal.Notice("api-spec", fmt.Sprintf(
			"Ingested %d API spec endpoints from discovery of %s — extra requests "+
				"queued for dynamic assessment (longer scan, more results)",
			total, c.target))
	}

	if c.refTotal > 0 {
		streamed := ""
		if c.refStreamed > 0 {
			streamed = fmt.Sprintf(" (%d streamed during the crawl)", c.refStreamed)
		}
		terminal.NoticeArrow("jstangle", fmt.Sprintf(
			"Preserved %d JS/form-referenced request(s)%s, kept out of fuzz-noise "+
				"dedup so real methods/bodies/baselines survive to assessment — %s",
			c.refTotal, streamed, terminal.Gray(c.target)))
	}

	// Update the discovery counters now; Imported/ImportFailed are merged by
	// the deferred block once the persistence below has run.
	d.mu.Lock()
	d.stats.TotalDiscovered += localStats.TotalDiscovered
	d.stats.HardDedupRemoved += localStats.HardDedupRemoved
	d.stats.FuzzyCappedRemoved += localStats.FuzzyCappedRemoved
	d.stats.ClusterCap = localStats.ClusterCap
	d.stats.TargetsTimedOut += localStats.TargetsTimedOut
	d.stats.SitemapCapped += engine.SitemapCapped()
	for i := range d.stats.AllCodes {
		d.stats.AllCodes[i] += localStats.AllCodes[i]
		d.stats.DedupedCodes[i] += localStats.DedupedCodes[i]
		d.stats.CappedCodes[i] += localStats.CappedCodes[i]
	}
	d.mu.Unlock()

	_, err := d.importCollected(ctx, c.siteMap, collectedGroups{
		sourceOrder:   sourceOrder,
		bySource:      bySource,
		specEndpoints: specEndpoints,
		jsTemplates:   jsPlan,
		acc:           c.acc,
	})
	if err != nil {
		return err
	}
	d.noteJSTemplateStats(c.target, jsPlan, c.acc.factBundles)

	if c.acc.imported > 0 || c.acc.failed > 0 {
		zap.L().Info("Deparos discovery results imported to DB",
			zap.String("target", c.target),
			zap.Int("discovered", localStats.TotalDiscovered),
			zap.Int("hard_dedup_removed", localStats.HardDedupRemoved),
			zap.Int("fuzzy_capped_removed", localStats.FuzzyCappedRemoved),
			zap.Int("cluster_cap", localStats.ClusterCap),
			zap.Int("referenced_preserved", c.refTotal),
			zap.Int("referenced_streamed", c.refStreamed),
			zap.Int("flushes", c.flushes),
			zap.Int("imported", c.acc.imported),
			zap.Int("import_failed", c.acc.failed))
	}
	return nil
}
