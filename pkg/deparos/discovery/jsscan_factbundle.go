package discovery

import (
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// maxBundledFactsPerKind bounds each kind in one asset's bundle. It matches the
// helper's own per-kind caps (maxPathLiterals, maxChunksPerRuntime), so a
// well-behaved helper never hits it; the overflow is counted in Truncated.
const maxBundledFactsPerKind = 2000

// JSFactBundle is everything jstangle reported about one JS asset that is not
// a replayable request template: routes (with fullPath), GraphQL operations,
// WebSocket/EventSource endpoints, asset references, browser security flows,
// path literals, and low-confidence request hints. These used to die with the
// ephemeral siteMap; the integrated source persists each bundle as one
// "jstangle-facts" analysis artifact on the asset's record, where read commands
// and the crawler can find them. JSON keys are the helper's fact kinds.
type JSFactBundle struct {
	SourceURL            string                             `json:"source_url"`
	ClientRoutes         []jstangle.ClientRouteFact         `json:"clientRoute,omitempty"`
	GraphQLOperations    []jstangle.GraphQLOperationFact    `json:"graphqlOperation,omitempty"`
	WebSockets           []jstangle.WebSocketFact           `json:"websocket,omitempty"`
	EventSources         []jstangle.EventSourceFact         `json:"eventSource,omitempty"`
	AssetReferences      []jstangle.AssetReferenceFact      `json:"assetReference,omitempty"`
	BrowserSecurityFlows []jstangle.BrowserSecurityFlowFact `json:"browserSecurityFlow,omitempty"`
	PathLiterals         []jstangle.PathLiteralFact         `json:"pathLiteral,omitempty"`
	// RequestHints are httpRequest facts that are never replayed: low
	// confidence, or a URL that starts with a variable.
	RequestHints []jstangle.HTTPRequestFact `json:"httpRequestHint,omitempty"`
	// Truncated counts facts per kind dropped by maxBundledFactsPerKind.
	Truncated map[string]int `json:"truncated,omitempty"`
}

// Len is the number of facts in the bundle.
func (b *JSFactBundle) Len() int {
	return len(b.ClientRoutes) + len(b.GraphQLOperations) + len(b.WebSockets) + len(b.EventSources) +
		len(b.AssetReferences) + len(b.BrowserSecurityFlows) + len(b.PathLiterals) + len(b.RequestHints)
}

type jsFactBundleState struct {
	bundle JSFactBundle
	seen   map[string]struct{}
}

// admit reports whether a fact of this kind/id is new and fits the kind's cap.
// count is the kind's current length.
func (s *jsFactBundleState) admit(kind, id string, count int) bool {
	if id != "" {
		key := kind + "\x00" + id
		if _, dup := s.seen[key]; dup {
			return false
		}
		s.seen[key] = struct{}{}
	}
	if count >= maxBundledFactsPerKind {
		if s.bundle.Truncated == nil {
			s.bundle.Truncated = make(map[string]int)
		}
		s.bundle.Truncated[kind]++
		return false
	}
	return true
}

// isRequestHint reports whether an httpRequest fact is a hint rather than a
// replay template (mirrors AddRequestFact's hint rule).
func isRequestHint(fact *jstangle.HTTPRequestFact) bool {
	return fact.Provenance.Confidence == "low" || strings.HasPrefix(strings.TrimSpace(fact.URL.Rendered), "${")
}

// collectJSFacts adds one scan result's non-request facts to its asset's
// bundle. The same asset can be analyzed more than once (stored JS, then a
// fetch); facts are deduplicated by kind and id.
func (e *Engine) collectJSFacts(sourceURL string, result *jstangle.ScanResult) {
	if result == nil || sourceURL == "" {
		return
	}
	e.jsFactsMu.Lock()
	defer e.jsFactsMu.Unlock()
	if e.jsFacts == nil {
		e.jsFacts = make(map[string]*jsFactBundleState)
	}
	state := e.jsFacts[sourceURL]
	if state == nil {
		state = &jsFactBundleState{bundle: JSFactBundle{SourceURL: sourceURL}, seen: make(map[string]struct{})}
		e.jsFacts[sourceURL] = state
	}
	b := &state.bundle
	for _, f := range result.ClientRoutes {
		if state.admit("clientRoute", f.ID, len(b.ClientRoutes)) {
			b.ClientRoutes = append(b.ClientRoutes, f)
		}
	}
	for _, f := range result.GraphQLOperations {
		if state.admit("graphqlOperation", f.ID, len(b.GraphQLOperations)) {
			b.GraphQLOperations = append(b.GraphQLOperations, f)
		}
	}
	for _, f := range result.WebSockets {
		if state.admit("websocket", f.ID, len(b.WebSockets)) {
			b.WebSockets = append(b.WebSockets, f)
		}
	}
	for _, f := range result.EventSources {
		if state.admit("eventSource", f.ID, len(b.EventSources)) {
			b.EventSources = append(b.EventSources, f)
		}
	}
	for _, f := range result.AssetFacts {
		if state.admit("assetReference", f.ID, len(b.AssetReferences)) {
			b.AssetReferences = append(b.AssetReferences, f)
		}
	}
	for _, f := range result.BrowserFlows {
		if state.admit("browserSecurityFlow", f.ID, len(b.BrowserSecurityFlows)) {
			b.BrowserSecurityFlows = append(b.BrowserSecurityFlows, f)
		}
	}
	for _, f := range result.PathLiterals {
		if state.admit("pathLiteral", f.ID, len(b.PathLiterals)) {
			b.PathLiterals = append(b.PathLiterals, f)
		}
	}
	for i := range result.RequestFacts {
		f := &result.RequestFacts[i]
		if isRequestHint(f) && state.admit("httpRequestHint", f.ID, len(b.RequestHints)) {
			b.RequestHints = append(b.RequestHints, cloneRequestFact(*f))
		}
	}
}

// JSFactBundles returns the non-request facts collected per JS asset, sorted by
// source URL, omitting assets that reported none. Read after Stop().
func (e *Engine) JSFactBundles() []JSFactBundle {
	e.jsFactsMu.Lock()
	defer e.jsFactsMu.Unlock()
	result := make([]JSFactBundle, 0, len(e.jsFacts))
	for _, state := range e.jsFacts {
		if state.bundle.Len() == 0 {
			continue
		}
		bundle := state.bundle
		if len(bundle.Truncated) > 0 {
			truncated := make(map[string]int, len(bundle.Truncated))
			for kind, n := range bundle.Truncated {
				truncated[kind] = n
			}
			bundle.Truncated = truncated
		}
		result = append(result, bundle)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SourceURL < result[j].SourceURL })
	return result
}
