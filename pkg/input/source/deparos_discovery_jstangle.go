package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// Persisting JS-derived request templates.
//
// The deparos engine only turns a JS template into a siteMap node when a
// replay of it was judged to exist. Everything else (a 404 or soft-404, a
// medium-confidence template under replay_mode exact, a POST withheld by
// replay_safety, a template the flush cap never reached) vanished with the
// per-target siteMap, although the code that found it is the best evidence
// the endpoint exists. After each target's crawl, every in-scope template
// that did not become a node is written as an http_records stub under
// jstangleRecordSource, tagged with jstangle:* remarks, with the full fact
// attached as a "jstangle-fact" analysis artifact.
//
// Emission is narrower than persistence, so persisting never makes discovery
// send something replay_safety withheld: a found template is emitted as it
// always was, a not-found replay is emitted only when its status says the
// route exists and wants different input (400/405/415/422 by default), and
// every other stub is persist-only.

const (
	// jstangleFactArtifactKind holds one template's full fact and outcome, on
	// the template's own record.
	jstangleFactArtifactKind = "jstangle-fact"
	// jstangleFactsArtifactKind holds one JS asset's non-request facts (routes,
	// GraphQL, WS/SSE, assets, browser flows, path literals, request hints).
	jstangleFactsArtifactKind = "jstangle-facts"

	// defaultMaxPersistedJSTemplates bounds the stubs one target may write.
	defaultMaxPersistedJSTemplates = 2000
)

// defaultJSNotFoundEmitStatuses are the not-found replay statuses that still
// mean "the route exists": bad request, method not allowed, unsupported media
// type, unprocessable entity.
var defaultJSNotFoundEmitStatuses = []int{400, 405, 415, 422}

// JSTemplatePersistConfig controls how JS-derived request templates that did
// not become discovery nodes are persisted. The zero value is the default.
type JSTemplatePersistConfig struct {
	// SkipUnreplayed stops persisting templates that were never sent
	// (withheld, deduped, unresolved). discovery.jstangle.persist_unreplayed:
	// false. Replayed-but-not-found templates are persisted regardless.
	SkipUnreplayed bool
	// EmitStatuses are the not-found replay statuses emitted to later phases.
	// nil means defaultJSNotFoundEmitStatuses; an empty non-nil slice emits none.
	EmitStatuses []int
	// MaxPerTarget caps the stubs written per target. 0 means
	// defaultMaxPersistedJSTemplates; negative means unlimited.
	MaxPerTarget int
}

func (c JSTemplatePersistConfig) emitStatuses() []int {
	if c.EmitStatuses == nil {
		return defaultJSNotFoundEmitStatuses
	}
	return c.EmitStatuses
}

func (c JSTemplatePersistConfig) maxPerTarget() int {
	switch {
	case c.MaxPerTarget == 0:
		return defaultMaxPersistedJSTemplates
	case c.MaxPerTarget < 0:
		return 0
	default:
		return c.MaxPerTarget
	}
}

// remarksAppender is the optional repository capability that annotates stored
// records. Primitive-typed so pkg/database satisfies it structurally.
type remarksAppender interface {
	AppendRemarks(ctx context.Context, annotations map[string][]string) error
}

// jsTemplateRecord is one template's persistence: a stub to save (rr non-nil)
// or an existing node to annotate (rr nil, nodeTarget set).
type jsTemplateRecord struct {
	rr         *httpmsg.HttpRequestResponse
	nodeTarget string
	outcome    discovery.TemplateOutcome
	remarks    []string
	priority   int
}

// jsTemplatePlan is one target's JS template persistence, computed after the
// crawl stops and before the siteMap closes.
type jsTemplatePlan struct {
	emit     []*jsTemplateRecord
	persist  []*jsTemplateRecord
	annotate []*jsTemplateRecord
	bundles  []discovery.JSFactBundle

	notFound   int            // replayed_not_found stubs planned
	withheld   map[string]int // withheld_* outcome -> templates
	capped     int            // stubs dropped by the per-target cap
	skippedLow int            // low-confidence templates left to the facts artifact
}

// nodeIndex locates the siteMap nodes a target imported, by method+URL and by
// URL alone, mapped to the record target used as the uuidByURL key.
type nodeIndex struct {
	byMethodURL map[string]string
	byURL       map[string]string
}

func newNodeIndex(sizeHint int) *nodeIndex {
	return &nodeIndex{byMethodURL: make(map[string]string, sizeHint), byURL: make(map[string]string, sizeHint)}
}

func (n *nodeIndex) add(method, nodeURL, target string) {
	n.byMethodURL[strings.ToUpper(method)+" "+nodeURL] = target
	if _, ok := n.byURL[nodeURL]; !ok {
		n.byURL[nodeURL] = target
	}
}

// stubPriority orders stubs for the per-target cap: what a later phase can use
// most comes first.
func stubPriority(o discovery.TemplateOutcome, emit bool) int {
	switch {
	case emit:
		return 0
	case o.Outcome == discovery.TemplateReplayedNotFound:
		return 1
	case o.Outcome == discovery.TemplateWithheldPolicy:
		return 2
	case o.Outcome == discovery.TemplateWithheldConfidence:
		return 3
	case o.Outcome == discovery.TemplateDeduped:
		return 4
	case o.Outcome == discovery.TemplateWithheldFlushCap:
		return 5
	default:
		return 6
	}
}

// planJSTemplates decides, per template outcome, whether it is skipped,
// annotates an existing node, or becomes an emitted or persist-only stub.
func planJSTemplates(
	outcomes []discovery.TemplateOutcome,
	nodes *nodeIndex,
	fallback *url.URL,
	cfg JSTemplatePersistConfig,
) *jsTemplatePlan {
	plan := &jsTemplatePlan{withheld: make(map[string]int)}
	emitStatuses := cfg.emitStatuses()
	var stubs []*jsTemplateRecord
	for _, o := range outcomes {
		switch o.Outcome {
		case discovery.TemplateWithheldPolicy, discovery.TemplateWithheldConfidence, discovery.TemplateWithheldFlushCap:
			plan.withheld[o.Outcome]++
		}
		if o.Outcome == discovery.TemplateOutOfScope {
			continue // never persisted: the project/scope contract
		}
		if o.Template.Confidence == "low" {
			// A hint, never a request: it lives in the jstangle-facts artifact.
			plan.skippedLow++
			continue
		}
		stub, ok := discovery.BuildTemplateStub(o.Template, fallback)
		if o.Replayed() && o.URL != "" {
			stub.URL, stub.Method, stub.MethodUnresolved, ok = o.URL, o.Method, false, true
		}
		if !ok || stub.URL == "" {
			continue
		}
		rec := &jsTemplateRecord{outcome: o, remarks: jsTemplateRemarks(o, stub)}

		target, exists := nodes.byMethodURL[strings.ToUpper(stub.Method)+" "+stub.URL]
		if !exists && o.Outcome == discovery.TemplateReplayedFound {
			target, exists = nodes.byURL[stub.URL]
		}
		if exists {
			// The crawl already imported this request: annotate it rather than
			// writing a second row.
			rec.nodeTarget = target
			plan.annotate = append(plan.annotate, rec)
			continue
		}
		if !o.Replayed() && cfg.SkipUnreplayed {
			continue
		}

		rr, err := jsTemplateStubRecord(stub, o)
		if err != nil {
			continue
		}
		rec.rr = rr
		emit := o.Outcome == discovery.TemplateReplayedFound ||
			(o.Outcome == discovery.TemplateReplayedNotFound && slices.Contains(emitStatuses, o.Status))
		rec.priority = stubPriority(o, emit)
		stubs = append(stubs, rec)
	}

	sort.SliceStable(stubs, func(i, j int) bool { return stubs[i].priority < stubs[j].priority })
	if limit := cfg.maxPerTarget(); limit > 0 && len(stubs) > limit {
		plan.capped = len(stubs) - limit
		stubs = stubs[:limit]
	}
	for _, rec := range stubs {
		if rec.outcome.Outcome == discovery.TemplateReplayedNotFound {
			plan.notFound++
		}
		if rec.priority == 0 {
			plan.emit = append(plan.emit, rec)
		} else {
			plan.persist = append(plan.persist, rec)
		}
	}
	return plan
}

// jsTemplateStubRecord builds the stored request for a stub, attaching the
// captured response when the template was replayed.
func jsTemplateStubRecord(stub discovery.TemplateStub, o discovery.TemplateOutcome) (*httpmsg.HttpRequestResponse, error) {
	headers := make(map[string]string, len(stub.Headers)+1)
	for _, header := range stub.Headers {
		name, value, found := strings.Cut(header, ":")
		if found && strings.TrimSpace(name) != "" {
			headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	if stub.Body != "" && stub.ContentType != "" && !hasHeaderCI(headers, "Content-Type") {
		headers["Content-Type"] = stub.ContentType
	}
	rr, err := httpmsg.GetRawRequestFromURLWithMethod(stub.URL, stub.Method, headers, []byte(stub.Body))
	if err != nil {
		return nil, err
	}
	if stub.Body == "" && (stub.Method == "" || strings.EqualFold(stub.Method, "GET")) && len(headers) > 0 {
		// The bodyless-GET shortcut builds a bare request; put the safe
		// headers back so the stub is the request the code would send.
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		sort.Strings(names)
		req := rr.Request()
		for _, name := range names {
			req = req.WithHeader(name, headers[name])
		}
		rr = httpmsg.NewHttpRequestResponse(req, nil)
	}
	if resp := o.Response; resp != nil && resp.StatusCode > 0 {
		raw := httpmsg.BuildRawResponse(resp.StatusCode, resp.Headers, string(resp.Body))
		rr = rr.WithResponse(httpmsg.NewHttpResponseWithDuration(raw, time.Duration(resp.DurationMs)*time.Millisecond))
	}
	return rr, nil
}

// jsTemplateRemarks are the jstangle:* remarks a template's record carries.
func jsTemplateRemarks(o discovery.TemplateOutcome, stub discovery.TemplateStub) []string {
	fact := &o.Template.Request
	remarks := []string{"jstangle:" + o.Outcome}
	if o.Reason != "" {
		remarks = append(remarks, "jstangle:reason="+o.Reason)
	}
	if o.Template.Confidence != "" {
		remarks = append(remarks, "jstangle:confidence="+o.Template.Confidence)
	}
	if fact.Provenance.Extractor != "" {
		remarks = append(remarks, "jstangle:extractor="+fact.Provenance.Extractor)
	}
	if o.Template.SourceURL != "" {
		src := "jstangle:src=" + o.Template.SourceURL
		if start := fact.Provenance.Start; start != nil && start.Line > 0 {
			src += fmt.Sprintf("#L%d", start.Line)
		}
		remarks = append(remarks, src)
	}
	if auth := fact.Auth; auth != nil && auth.Kind != "" {
		remarks = append(remarks, "jstangle:auth="+auth.Kind+":"+auth.Source)
	}
	if stub.MethodUnresolved {
		remarks = append(remarks, "jstangle:method=unresolved")
	}
	return remarks
}

// jstangleFactDocument is the jstangle-fact artifact body.
type jstangleFactDocument struct {
	SourceURL  string `json:"source_url"`
	TemplateID string `json:"template_id"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
	Status     int    `json:"status,omitempty"`
	Method     string `json:"method,omitempty"`
	URL        string `json:"url,omitempty"`
	Fact       any    `json:"fact"`
}

// importJSTemplates persists one target's JS template plan: emitted stubs,
// persist-only stubs, remarks on every template's record, the per-template
// fact artifacts, and the per-asset facts artifacts. Runs after the target's
// other groups so annotated nodes and asset records already have UUIDs.
func (d *DeparosDiscoverySource) importJSTemplates(ctx context.Context, acc *importAccum, plan *jsTemplatePlan) error {
	if plan == nil {
		return nil
	}
	emitUUIDs, err := d.importRecords(ctx, acc, jsTemplateRRs(plan.emit), jstangleRecordSource, true)
	if err != nil {
		return err
	}
	persistUUIDs, err := d.importRecords(ctx, acc, jsTemplateRRs(plan.persist), jstangleRecordSource, false)
	if err != nil {
		return err
	}

	type annotated struct {
		uuid string
		rec  *jsTemplateRecord
	}
	var targets []annotated
	collect := func(records []*jsTemplateRecord, uuids []string) {
		for i, rec := range records {
			if i < len(uuids) && uuids[i] != "" {
				targets = append(targets, annotated{uuids[i], rec})
			}
		}
	}
	collect(plan.emit, emitUUIDs)
	collect(plan.persist, persistUUIDs)
	for _, rec := range plan.annotate {
		if uuid := acc.uuidByURL[rec.nodeTarget]; uuid != "" {
			targets = append(targets, annotated{uuid, rec})
		}
	}
	if len(targets) == 0 && len(plan.bundles) == 0 {
		return nil
	}

	if appender, ok := d.cfg.Repository.(remarksAppender); ok && len(targets) > 0 {
		annotations := make(map[string][]string, len(targets))
		for _, t := range targets {
			annotations[t.uuid] = append(annotations[t.uuid], t.rec.remarks...)
		}
		if err := appender.AppendRemarks(ctx, annotations); err != nil {
			zap.L().Debug("Failed to tag JS template records", zap.Error(err))
		}
	}

	saver, ok := d.cfg.Repository.(analysisArtifactSaver)
	if !ok {
		return nil
	}
	for _, t := range targets {
		o := t.rec.outcome
		doc, err := json.Marshal(jstangleFactDocument{
			SourceURL: o.Template.SourceURL, TemplateID: o.Template.ID,
			Outcome: o.Outcome, Reason: o.Reason, Status: o.Status, Method: o.Method, URL: o.URL,
			Fact: o.Template.Request,
		})
		if err != nil {
			continue
		}
		meta, _ := json.Marshal(map[string]string{
			"source_url": o.Template.SourceURL, "template_id": o.Template.ID, "outcome": o.Outcome,
		})
		if err := saveJSONArtifact(ctx, saver, t.uuid, jstangleFactArtifactKind, o.Template.ID+".json", doc, string(meta)); err != nil {
			zap.L().Debug("Failed to store jstangle-fact artifact", zap.String("template", o.Template.ID), zap.Error(err))
		}
	}
	acc.factBundles += d.persistJSFactBundles(ctx, saver, plan.bundles, acc.uuidByURL)
	return nil
}

// persistJSFactBundles stores each asset's non-request facts as one
// jstangle-facts artifact, anchored to the asset's record or, when the asset
// was not recorded (inline scripts, source-map virtual URLs, deduped bodies),
// to its origin's record. Returns how many were stored.
func (d *DeparosDiscoverySource) persistJSFactBundles(
	ctx context.Context,
	saver analysisArtifactSaver,
	bundles []discovery.JSFactBundle,
	uuidByURL map[string]string,
) int {
	var originAnchors map[string]string
	stored := 0
	for i := range bundles {
		bundle := &bundles[i]
		uuid := uuidByURL[bundle.SourceURL]
		if uuid == "" {
			if originAnchors == nil {
				originAnchors = originAnchorRecords(uuidByURL)
			}
			uuid = originAnchors[originOf(bundle.SourceURL)]
		}
		if uuid == "" {
			continue
		}
		content, err := json.Marshal(bundle)
		if err != nil {
			continue
		}
		meta, _ := json.Marshal(map[string]any{"source_url": bundle.SourceURL, "facts": bundle.Len()})
		digest := sha256.Sum256([]byte(bundle.SourceURL))
		filename := "jstangle-facts-" + hex.EncodeToString(digest[:8]) + ".json"
		if err := saveJSONArtifact(ctx, saver, uuid, jstangleFactsArtifactKind, filename, content, string(meta)); err != nil {
			zap.L().Debug("Failed to store jstangle-facts artifact", zap.String("source", bundle.SourceURL), zap.Error(err))
			continue
		}
		stored++
	}
	return stored
}

func saveJSONArtifact(ctx context.Context, saver analysisArtifactSaver, recordUUID, kind, filename string, content []byte, metadata string) error {
	digest := sha256.Sum256(content)
	return saver.SaveAnalysisArtifact(ctx, recordUUID, kind, filename, "application/json",
		hex.EncodeToString(digest[:]), content, metadata)
}

func jsTemplateRRs(records []*jsTemplateRecord) []*httpmsg.HttpRequestResponse {
	out := make([]*httpmsg.HttpRequestResponse, 0, len(records))
	for _, rec := range records {
		out = append(out, rec.rr)
	}
	return out
}

// importRecords persists one group under label, emitting it as work items when
// emit is set and the consumer is still reading, and counts the outcome into
// acc. It returns the persisted UUIDs aligned with records.
func (d *DeparosDiscoverySource) importRecords(
	ctx context.Context,
	acc *importAccum,
	records []*httpmsg.HttpRequestResponse,
	label string,
	emit bool,
) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	var uuids []string
	if emit && acc.emit {
		var err error
		uuids, err = d.saveAndEmitWithUUIDs(ctx, records, label)
		switch {
		case errors.Is(err, errEmitStopped):
			// Saved, but the hand-off stopped. Keep persisting the rest.
			acc.emit = false
		case err != nil:
			return uuids, err
		}
	} else {
		uuids = d.persistOnly(ctx, records, label)
	}

	noRepository := d.cfg.Repository == nil
	for i, rr := range records {
		if rr == nil {
			continue
		}
		uuid := ""
		if i < len(uuids) {
			uuid = uuids[i]
		}
		switch {
		case uuid != "":
			acc.uuidByURL[rr.Target()] = uuid
			acc.imported++
		case noRepository:
			acc.imported++
		default:
			acc.failed++
		}
	}
	return uuids, nil
}

// noteJSTemplateStats folds one target's plan into the source's counters and
// logs it.
func (d *DeparosDiscoverySource) noteJSTemplateStats(target string, plan *jsTemplatePlan, bundlesStored int) {
	if plan == nil {
		return
	}
	persisted := len(plan.emit) + len(plan.persist)
	d.mu.Lock()
	d.stats.JSFactsPersisted += persisted
	d.stats.JSFactsNotFound += plan.notFound
	d.stats.JSTemplatesCapped += plan.capped
	d.stats.JSFactBundles += bundlesStored
	for reason, n := range plan.withheld {
		if d.stats.JSFactsWithheld == nil {
			d.stats.JSFactsWithheld = make(map[string]int)
		}
		d.stats.JSFactsWithheld[reason] += n
	}
	d.mu.Unlock()

	if persisted == 0 && len(plan.annotate) == 0 && bundlesStored == 0 && plan.capped == 0 {
		return
	}
	withheld := 0
	for _, n := range plan.withheld {
		withheld += n
	}
	zap.L().Info("JS templates persisted from discovery",
		zap.String("target", target),
		zap.Int("persisted", persisted),
		zap.Int("emitted", len(plan.emit)),
		zap.Int("not_found", plan.notFound),
		zap.Int("withheld", withheld),
		zap.Any("withheld_by_outcome", plan.withheld),
		zap.Int("annotated_nodes", len(plan.annotate)),
		zap.Int("low_confidence_hints", plan.skippedLow),
		zap.Int("capped", plan.capped),
		zap.Int("fact_bundles", bundlesStored))
	if plan.capped > 0 {
		zap.L().Warn("JS template persistence hit its per-target cap",
			zap.String("target", target), zap.Int("dropped", plan.capped),
			zap.String("limit", "js_template_persist_cap"))
	}
}
