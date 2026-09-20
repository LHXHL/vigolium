package sourcemap_detect

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxSourcesOutput caps the number of source paths included in finding output.
const maxSourcesOutput = 20

// Module detects exposed JavaScript sourcemaps in production responses.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new sourcemap exposure detection passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_sourcemap_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS/CSS responses (for SourceMappingURL detection) and
// URLs ending in .map (for sourcemap file validation).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	if u, err := ctx.URL(); err == nil && sourcemap.IsMapPath(u.Path) {
		return true
	}

	ct := ctx.Response().Header("Content-Type")
	return isJSOrCSSContentType(ct)
}

// ScanPerRequest analyzes the response for sourcemap indicators.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if ctx.Response() == nil || modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Detection 2: .map file response with valid sourcemap JSON
	if sourcemap.IsMapPath(urlx.Path) {
		return m.detectMapFile(ctx, urlx.String(), urlx.Host)
	}

	// Detection 1: SourceMappingURL reference in JS/CSS body
	return m.detectSourceMappingURL(ctx, urlx.String(), urlx.Host)
}

// detectSourceMappingURL reports the source-map references a JS/CSS body carries.
//
// Extraction is delegated to the shared sourcemap package so this module sees the
// same reference forms the active ingest module and the discovery crawl do — the
// CSS block comment and the escaped reference inside a webpack eval module
// included, neither of which the module's own regex matched.
//
// It stays passive: an external map is never fetched here. The active
// sourcemap-ingest module is what confirms the exposure and recovers the source,
// so this finding deliberately remains an observation.
func (m *Module) detectSourceMappingURL(ctx *httpmsg.HttpRequestResponse, urlStr, host string) ([]*output.ResultEvent, error) {
	references := sourcemap.ExtractReferences(ctx.Response().Body())
	if len(references) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, reference := range references {
		// An inline map needs nothing fetched: its content is already in the body,
		// so the disclosure is complete and can be reported as such.
		if len(reference.Inline) > 0 {
			if document, err := sourcemap.Parse(reference.Inline, urlStr); err == nil && isSubstantiveMap(document) {
				return m.mapResult(ctx, urlStr, host, document, true), nil
			}
			results = append(results, m.referenceEvent(ctx, urlStr, host,
				fmt.Sprintf("inline source map data URI (%d bytes; structure not validated)", len(reference.Inline)),
				map[string]any{
					"map_url":                    "<inline source map data URI>",
					"map_retrieved":              false,
					"unauthorized_access_tested": false,
					"has_inline":                 true,
					"reference_origin":           string(reference.Origin),
				}))
			continue
		}

		mapReference := safeMapReference(reference.URL)
		results = append(results, m.referenceEvent(ctx, urlStr, host,
			mapReference,
			map[string]any{
				"map_url":                    mapReference,
				"map_retrieved":              false,
				"unauthorized_access_tested": false,
				"reference_origin":           string(reference.Origin),
			}))
	}

	return results, nil
}

// referenceEvent renders the unconfirmed-reference observation.
func (m *Module) referenceEvent(
	ctx *httpmsg.HttpRequestResponse,
	urlStr, host, extracted string,
	meta map[string]any,
) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindObservation,
		EvidenceGrade: output.EvidenceGradeObservation,
		Info: output.Info{
			Name: "SourceMappingURL Reference",
			Description: "JavaScript/CSS contains a sourceMappingURL reference. An external map was not fetched by " +
				"this passive module, so source availability and sensitive content are unconfirmed; the active " +
				"sourcemap-ingest module fetches and parses the map when it runs.",
			Severity:   severity.Low,
			Confidence: severity.Firm,
			Tags:       []string{"sourcemap", "information-disclosure", "javascript"},
		},
		Host:             host,
		URL:              urlStr,
		Matched:          urlStr,
		Request:          string(ctx.Request().Raw()),
		Response:         string(ctx.Response().Raw()),
		ExtractedResults: []string{extracted},
		Metadata:         meta,
	}
}

// detectMapFile validates that a .map response contains valid sourcemap JSON.
func (m *Module) detectMapFile(ctx *httpmsg.HttpRequestResponse, urlStr, host string) ([]*output.ResultEvent, error) {
	if status := ctx.Response().StatusCode(); status < 200 || status >= 300 {
		return nil, nil
	}
	document, err := sourcemap.Parse(ctx.Response().Body(), urlStr)
	if err != nil || !isSubstantiveMap(document) {
		return nil, nil
	}
	return m.mapResult(ctx, urlStr, host, document, false), nil
}

// isSubstantiveMap rejects a v3-shaped JSON blob that names nothing and maps
// nothing. Reporting one as a source map would be a finding about a file that
// discloses no source and no layout.
func isSubstantiveMap(document *sourcemap.Document) bool {
	return len(document.SourcePaths) > 0 && document.HasMappings
}

// mapResult renders the finding for a map this module actually saw the body of.
// Parsing goes through the shared bounded parser: this module's own decoder read
// every embedded source into memory with none of the size budgets applied, and
// accepted any positive version where the parser requires 3 — so the passive and
// active modules could disagree about whether the same body was a map.
func (m *Module) mapResult(ctx *httpmsg.HttpRequestResponse, urlStr, host string, document *sourcemap.Document, inline bool) []*output.ResultEvent {

	sev := severity.Low
	conf := severity.Certain
	tags := []string{"sourcemap", "information-disclosure", "javascript"}

	hasSourceContent := document.HasEmbeddedContent()
	if hasSourceContent {
		sev = severity.Medium
		tags = append(tags, "source-code")
	}

	// Cap extracted sources
	sources := document.SourcePaths
	if len(sources) > maxSourcesOutput {
		sources = sources[:maxSourcesOutput]
	}

	desc := fmt.Sprintf("A structurally valid source map with %d source entries was delivered to this client", len(document.SourcePaths))
	if hasSourceContent {
		desc += " and includes embedded source text"
	}
	desc += ". This is a source-exposure candidate; production intent, anonymous access, and sensitive content were not established."
	name := "Sourcemap File Accessible"
	if inline {
		name = "Inline Sourcemap Embedded"
	}

	return []*output.ResultEvent{
		{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    sev,
				Confidence:  conf,
				Tags:        tags,
			},
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: sources,
			Metadata: map[string]any{
				"version":                    3,
				"source_count":               len(document.SourcePaths),
				"has_source_content":         hasSourceContent,
				"inline":                     inline,
				"anonymous_access_tested":    false,
				"sensitive_content_detected": false,
			},
		},
	}
}

// safeMapReference renders a reference URL for output, query and fragment
// stripped and length-bounded. Inline maps never reach it: ExtractReferences
// returns those as decoded content with no URL.
func safeMapReference(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return modkit.Truncate(value, 160)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return modkit.Truncate(parsed.String(), 160)
}

// isJSOrCSSContentType checks if the content type indicates JavaScript or CSS.
func isJSOrCSSContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "text/css")
}
