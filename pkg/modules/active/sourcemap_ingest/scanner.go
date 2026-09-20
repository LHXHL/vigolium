// Package sourcemap_ingest recovers an application's original source from an
// exposed source map and feeds the routes it names back into the scan.
//
// It is the scanning-phase counterpart to what the discovery crawl does through
// its asset graph. The two exist separately because they are reached differently:
// discovery follows a bundle it just fetched, while this module sees one stored
// response at a time and is the only path that runs at all for `run scan`, for
// traffic ingested from a proxy, and for Burp/HAR imports — none of which run
// deparos.
//
// Its relationship to api_spec_ingest is deliberate and close: an exposed source
// map is the same class of find as an exposed OpenAPI document — a machine-readable
// description of the application's surface — and is handled the same way, by
// parsing it and feeding what it describes into the pipeline.
package sourcemap_ingest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// maxMapBytes caps one fetched map. Matches the parser's own limit.
	maxMapBytes = sourcemap.MaxMapBytes
	// maxMapsPerHost bounds how many maps one host may cost a scan. An SPA with
	// dozens of lazy chunks would otherwise dominate the phase, and the first
	// handful of maps already establish the exposure and most of the surface.
	maxMapsPerHost = 12
	// maxFedRoutesPerMap caps the routes one map contributes to the scan queue.
	maxFedRoutesPerMap = 200
	// maxReportedSources caps how many recovered paths appear in the finding.
	maxReportedSources = 25
)

// Module is the active source-map ingest scanner.
type Module struct {
	modkit.BaseActiveModule
	// ds holds all three scopes under distinct key prefixes — one asset lookup per
	// bundle, one parse per distinct map body, one budget counter per host. Each
	// dedup.Lazy key is a separate on-disk store, so prefixes are cheaper than
	// three of them for one module.
	ds dedup.Lazy[dedup.DiskSet]
}

func assetKey(assetURL string) string  { return "asset|" + assetURL }
func mapKey(contentHash string) string { return "map|" + contentHash }
func hostKey(host string) string       { return "host|" + host }

// New creates a new Source Map Ingest module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("sourcemap_ingest"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts responses for assets that can carry a source map.
//
// The gate is the path extension, not the content-type: static hosts label
// bundles inconsistently, and the sibling probe has to run even on a bundle whose
// own body says nothing. Matching on the path alone also keeps the gate working
// for a raw request whose scheme the record has not resolved yet.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	// Path() reads the request line directly, so the gate holds even for a record
	// whose service (and therefore scheme) is not attached yet; ScanPerRequest is
	// where a resolvable absolute URL becomes a requirement.
	return sourcemap.IsMappableAssetPath(ctx.Request().Path())
}

// IncludesBaseCanProcess returns false because CanProcess is fully overridden.
func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	assetURL := urlx.Scheme + "://" + urlx.Host + urlx.Path
	requestID := ctx.Request().ID()

	ds := m.ds.Get(scanCtx.DedupMgr())

	// One map lookup per asset, however many requests to it the scan sees.
	if ds != nil && ds.IsSeen(assetKey(assetURL)) {
		return nil, nil
	}

	// Candidate selection reads the whole body and the anonymous clone copies the
	// raw request, so both come after the host budget: an SPA with 200 chunks would
	// otherwise pay for all of them long after the 12-map budget was spent.
	if ds != nil {
		if _, ok := ds.IncrementAndCheck(hostKey(urlx.Host), maxMapsPerHost); !ok {
			return nil, nil
		}
	}

	candidates := sourcemap.CandidatesFor(assetURL, responseHeader(ctx), responseBody(ctx))
	if len(candidates) == 0 {
		return nil, nil
	}

	// Source maps must be shown to be readable by an anonymous client: one served
	// only to an authenticated session is a far weaker finding, and the scan's own
	// credentials would otherwise manufacture the exposure.
	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(ctx.Service(), cleanRaw),
		ctx.Response(),
	)

	var results []*output.ResultEvent
	for _, candidate := range candidates {
		if event := m.ingestMap(anonymousCtx, anonymousClient, scanCtx, ds, requestID, assetURL, candidate); event != nil {
			results = append(results, event)
		}
	}
	return results, nil
}

// responseHeader adapts a stored response to the header lookup CandidatesFor
// takes. Returns nil when there is no response to read.
func responseHeader(ctx *httpmsg.HttpRequestResponse) func(string) string {
	if ctx.Response() == nil {
		return nil
	}
	return ctx.Response().Header
}

func responseBody(ctx *httpmsg.HttpRequestResponse) []byte {
	if ctx.Response() == nil {
		return nil
	}
	return ctx.Response().Body()
}

// ingestMap fetches one candidate, parses it, feeds the routes it names, and
// returns the exposure finding. A candidate that does not resolve to a real map
// yields nothing — importantly including a catch-all host's 200 HTML shell.
func (m *Module) ingestMap(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	ds *dedup.DiskSet,
	requestID, assetURL string,
	candidate sourcemap.Candidate,
) *output.ResultEvent {
	body := candidate.Inline
	if len(body) == 0 {
		fetched, ok := fetchMap(ctx, httpClient, candidate.URL)
		if !ok {
			return nil
		}
		body = fetched
	}
	if !sourcemap.LooksLikeMap(body) {
		return nil
	}

	// One parse per distinct map body: content-hashed bundles routinely ship the
	// same map under several names, and a scan re-reaching the same asset must not
	// re-report it.
	contentHash := fmt.Sprintf("%x", sha256.Sum256(body))
	if ds != nil && ds.IsSeen(mapKey(contentHash)) {
		return nil
	}

	document, err := sourcemap.Parse(body, assetURL)
	if err != nil || (len(document.Sources) == 0 && len(document.SourcePaths) == 0) {
		return nil
	}

	fed := m.feedRecoveredRoutes(scanCtx, assetURL, document)
	if fed > 0 {
		terminal.Notice("sourcemap", fmt.Sprintf(
			"Recovered original source from %s — auto-ingesting %d route(s) "+
				"(extra traffic queued: scan takes longer but yields more results)",
			mapLocation(assetURL, candidate), fed))
	}
	m.storeRecoveredSources(context.Background(), scanCtx, requestID, assetURL, document)
	return m.buildEvent(ctx, assetURL, candidate, document, fed)
}

// storeRecoveredSources persists each recovered original file beside the bundle's
// record, under the same artifact kind the discovery crawl writes.
//
// Without this the module recovers the source, mines it for routes and throws it
// away — and the known-issue-scan pass that scans source-map originals for
// secrets (the whole reason recovering them is worth more than reading the
// bundle) finds nothing on exactly the paths this module exists to cover: run
// scan, proxy traffic, and Burp/HAR imports, none of which run the crawl.
func (m *Module) storeRecoveredSources(
	ctx context.Context,
	scanCtx *modkit.ScanContext,
	requestID, assetURL string,
	document *sourcemap.Document,
) {
	writer := scanCtx.DerivedArtifactWriterOrNil()
	if writer == nil || len(document.Sources) == 0 || scanCtx.RequestUUIDResolver == nil {
		return
	}
	recordUUID := scanCtx.RequestUUIDResolver.ResolveRequestUUID(requestID)
	if recordUUID == "" {
		return
	}
	for _, source := range document.Sources {
		err := writer.StoreDerivedArtifact(ctx, &modkit.DerivedArtifact{
			RecordUUID: recordUUID,
			Kind:       sourcemap.ArtifactKindOriginal,
			Filename:   source.Path,
			MediaType:  "application/javascript",
			SHA256:     source.ContentSHA256,
			Content:    source.Content,
			Metadata: map[string]any{
				"generated_url": assetURL,
				"source_path":   source.Path,
				"language":      source.Language,
			},
		})
		if err != nil {
			return
		}
	}
}

// feedRecoveredRoutes injects the endpoints named by the recovered sources back
// into the scan.
//
// Extraction runs over the original sources rather than the shipped bundle
// because that is the whole point of having the map: the pre-build code names its
// routes as readable literals, while the bundle may have concatenated or
// name-mangled them. Only same-origin relative paths are fed; an absolute URL
// elsewhere is another host's problem and is left to scope expansion.
func (m *Module) feedRecoveredRoutes(scanCtx *modkit.ScanContext, assetURL string, document *sourcemap.Document) int {
	feeder := scanCtx.Feeder()
	if feeder == nil {
		return 0
	}
	base, err := url.Parse(assetURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return 0
	}
	origin := base.Scheme + "://" + base.Host

	seen := make(map[string]struct{})
	fed := 0
	for _, source := range document.Sources {
		for _, recovered := range linkfinder.ExtractPaths(source.Content) {
			if fed >= maxFedRoutesPerMap {
				return fed
			}
			if !strings.HasPrefix(recovered, "/") {
				continue
			}
			// A build-graph path (src/…, node_modules/…) is a file on the developer's
			// machine, not a route; requesting it would be pure noise.
			if looksLikeBuildPath(recovered) {
				continue
			}
			target := origin + recovered
			if _, dup := seen[target]; dup {
				continue
			}
			seen[target] = struct{}{}
			rr, buildErr := httpmsg.GetRawRequestFromURL(target)
			if buildErr != nil {
				continue
			}
			if feeder.Feed(rr) {
				fed++
			}
		}
	}
	return fed
}

// buildPathPrefixes are directories that exist in the build tree, never on the
// server. A path under one is a source location the map disclosed, not a route.
//
// Source extensions (.ts, .tsx, .scss, …) and node_modules are deliberately
// absent: linkfinder.ExtractPaths already drops them via its own unwantedExts
// table, and a second blocklist here would only be one more thing to keep in
// sync with it.
var buildPathPrefixes = []string{
	"/src/", "/webpack/", "/lib/esm/", "/lib/cjs/",
	"/packages/", "/app/src/", "/client/src/", "/.pnpm/",
}

func looksLikeBuildPath(candidate string) bool {
	lowered := strings.ToLower(candidate)
	for _, prefix := range buildPathPrefixes {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	// .svelte is the one source extension linkfinder does not filter.
	return strings.HasSuffix(lowered, ".svelte")
}

// buildEvent renders the exposure finding.
//
// Severity tracks what the map actually gave up: embedded original source is a
// source-code disclosure, while a map stripped of sourcesContent discloses only
// the project's internal layout and is reported lower.
func (m *Module) buildEvent(
	ctx *httpmsg.HttpRequestResponse,
	assetURL string,
	candidate sourcemap.Candidate,
	document *sourcemap.Document,
	fed int,
) *output.ResultEvent {
	host := ""
	if parsed, err := url.Parse(assetURL); err == nil {
		host = parsed.Host
	}

	sev := severity.Low
	name := "Source Map Path Disclosure"
	description := fmt.Sprintf(
		"A source map for %s is readable anonymously. It embeds no original source text, "+
			"but names %d source files, disclosing the project's internal layout.",
		assetURL, len(document.SourcePaths))
	if document.HasEmbeddedContent() {
		sev = severity.Medium
		name = "Source Map Exposes Original Source"
		description = fmt.Sprintf(
			"A source map for %s is readable anonymously and embeds the original pre-build source of "+
				"%d files. The recovered code retains identifier names, comments and any hardcoded "+
				"values that minification would have obscured.",
			assetURL, len(document.Sources))
	}
	if candidate.Origin == sourcemap.OriginGuessed {
		description += " The bundle carries no sourceMappingURL reference — the map was found at its " +
			"conventional path, so stripping the comment did not remove the exposure."
	}
	if fed > 0 {
		description += fmt.Sprintf(" %d route(s) recovered from the sources have been ingested into the scan.", fed)
	}

	reported := append([]string(nil), document.SourcePaths...)
	sort.Strings(reported)
	if len(reported) > maxReportedSources {
		reported = reported[:maxReportedSources]
	}

	// Impact grade: unlike the passive detector, which only reports that a
	// reference exists, this module fetched the map anonymously and holds the
	// recovered source. The disclosure is demonstrated, not inferred.
	grade := output.EvidenceGradeImpact
	if !document.HasEmbeddedContent() {
		grade = output.EvidenceGradeCandidate
	}

	event := &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindFinding,
		EvidenceGrade: grade,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        ModuleTags,
		},
		Host:             host,
		URL:              mapLocation(assetURL, candidate),
		Matched:          mapLocation(assetURL, candidate),
		ExtractedResults: reported,
		Metadata: map[string]any{
			"asset_url":           assetURL,
			"map_url":             mapLocation(assetURL, candidate),
			"reference_origin":    string(candidate.Origin),
			"source_count":        len(document.SourcePaths),
			"has_source_content":  document.HasEmbeddedContent(),
			"recovered_sources":   len(document.Sources),
			"routes_ingested":     fed,
			"anonymous_access":    true,
			"external_sections":   len(document.ExternalSections),
			"contentless_sources": len(document.FetchableSources),
		},
	}
	if ctx.Request() != nil {
		event.Request = string(ctx.Request().Raw())
	}
	return event
}

// mapLocation names where a candidate was read from. An inline map has no URL of
// its own — it is embedded in the asset.
func mapLocation(assetURL string, candidate sourcemap.Candidate) string {
	if candidate.URL == "" {
		return assetURL + " (inline)"
	}
	return candidate.URL
}

// fetchMap retrieves a candidate map. The catch-all/blocked/pooled-buffer guards
// live in modkit.FetchAssetBytes; LooksLikeMap downstream rejects anything that
// slips past them and still is not a map document.
func fetchMap(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, mapURL string) ([]byte, bool) {
	parsed, err := url.Parse(mapURL)
	if err != nil {
		return nil, false
	}
	return modkit.FetchAssetBytes(ctx, httpClient, parsed.RequestURI(), maxMapBytes)
}
