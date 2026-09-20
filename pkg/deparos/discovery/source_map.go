package discovery

import (
	"context"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"go.uber.org/zap"
)

func annotateSourceMapProvenance(provenance *jstangle.Provenance, source sourcemap.OriginalSource) {
	if provenance == nil {
		return
	}
	provenance.ModulePath = source.Path
	for _, step := range provenance.ResolutionSteps {
		if step.Kind == "source-map" && step.Name == source.Path && step.Value == source.GeneratedSourceURL {
			return
		}
	}
	provenance.ResolutionSteps = append(provenance.ResolutionSteps, jstangle.ResolutionStep{
		Kind: "source-map", Name: source.Path, Value: source.GeneratedSourceURL,
	})
}

// annotateSourceMappedResult applies the original/generated source relationship
// uniformly to every typed record family before any fact is queued or persisted.
// Source locations already refer to the recovered original source; the bounded
// resolution step links those locations back to the generated bundle.
func annotateSourceMappedResult(result *jstangle.ScanResult, source sourcemap.OriginalSource) {
	if result == nil {
		return
	}
	for i := range result.RequestFacts {
		annotateSourceMapProvenance(&result.RequestFacts[i].Provenance, source)
	}
	for i := range result.DomFlowFacts {
		annotateSourceMapProvenance(&result.DomFlowFacts[i].Provenance, source)
	}
	for i := range result.AssetFacts {
		annotateSourceMapProvenance(&result.AssetFacts[i].Provenance, source)
	}
	for i := range result.GraphQLOperations {
		annotateSourceMapProvenance(&result.GraphQLOperations[i].Provenance, source)
	}
	for i := range result.WebSockets {
		annotateSourceMapProvenance(&result.WebSockets[i].Provenance, source)
	}
	for i := range result.EventSources {
		annotateSourceMapProvenance(&result.EventSources[i].Provenance, source)
	}
	for i := range result.ClientRoutes {
		annotateSourceMapProvenance(&result.ClientRoutes[i].Provenance, source)
	}
	for i := range result.BrowserFlows {
		annotateSourceMapProvenance(&result.BrowserFlows[i].Provenance, source)
	}
}

func (e *Engine) processAssetFacts(ctx context.Context, parentURL string, source []byte, facts []jstangle.AssetReferenceFact) {
	if len(facts) == 0 {
		return
	}
	graph := e.assetGraph()
	graph.AddRoot(parentURL, AssetScript)
	queued := make([]*url.URL, 0, len(facts))
	for _, fact := range facts {
		if fact.AssetType == string(AssetSourceMap) && !e.config.JSTangle.SourceMaps {
			continue
		}
		if fact.AssetType != string(AssetSourceMap) && !e.config.JSTangle.AssetGraph {
			continue
		}
		if fact.AssetType == string(AssetSourceMap) && fact.Inline {
			for _, reference := range sourcemap.ExtractReferences(source) {
				if len(reference.Inline) > 0 {
					e.processSourceMapContent(ctx, parentURL, reference.Inline)
				}
			}
			continue
		}
		resolved, added, reason := graph.Add(parentURL, fact.URL.Rendered, AssetKind(fact.AssetType))
		if !added {
			if reason != "duplicate-url" && reason != "" {
				logger.Debug("JS asset graph rejected reference", zap.String("parent", parentURL), zap.String("asset", fact.URL.Rendered), zap.String("reason", reason))
			}
			continue
		}
		if resolved == nil || e.spiderScope == nil || !e.spiderScope.IsInScope(resolved) {
			continue
		}
		if fact.AssetType != string(AssetWASM) {
			queued = append(queued, resolved)
		}
	}
	if len(queued) > 0 {
		e.queueJSFetch(queued, ProvenanceReferenced)
	}
}

// processSourceMapCandidates queues the maps an asset points at: inline ones are
// parsed on the spot, external ones go through the asset graph so its per-parent,
// per-host and total budgets bound the fan-out.
//
// A guessed sibling is queued as a guess, not as a reference — it is discovery
// asking "is a map deployed here?", and the prefix breaker must still be able to
// shut that down under a trap directory.
func (e *Engine) processSourceMapCandidates(ctx context.Context, parentURL string, candidates []sourcemap.Candidate) {
	if !e.config.JSTangle.SourceMaps || len(candidates) == 0 {
		return
	}
	graph := e.assetGraph()
	graph.AddRoot(parentURL, AssetScript)

	var referenced, guessed []*url.URL
	for _, candidate := range candidates {
		if len(candidate.Inline) > 0 {
			e.processSourceMapContent(ctx, parentURL, candidate.Inline)
			continue
		}
		resolved, added, reason := graph.Add(parentURL, candidate.URL, AssetSourceMap)
		if !added {
			if reason != "duplicate-url" && reason != "" {
				logger.Debug("Source-map candidate rejected", zap.String("parent", parentURL),
					zap.String("candidate", candidate.URL), zap.String("reason", reason))
			}
			continue
		}
		if resolved == nil || e.spiderScope == nil || !e.spiderScope.IsInScope(resolved) {
			continue
		}
		if candidate.Origin == sourcemap.OriginGuessed {
			guessed = append(guessed, resolved)
			continue
		}
		referenced = append(referenced, resolved)
	}
	e.queueJSFetch(referenced, ProvenanceReferenced)
	e.queueJSFetch(guessed, ProvenanceGuessed)
}

func (e *Engine) processSourceMapResponse(ctx context.Context, mapURL *url.URL, content []byte) {
	if !e.config.JSTangle.SourceMaps || mapURL == nil || len(content) == 0 {
		return
	}
	// A guessed sibling path on a catch-all host answers 200 with the SPA shell.
	// Reject that before parsing so a soft-404 cannot be mistaken for a map.
	if !sourcemap.LooksLikeMap(content) {
		logger.Debug("Source-map response is not a map document", zap.String("url", mapURL.String()))
		return
	}
	parents := e.assetGraph().Parents(mapURL.String())
	if len(parents) == 0 {
		parents = []string{strings.TrimSuffix(mapURL.String(), ".map")}
	}
	for _, generatedURL := range parents {
		e.processSourceMapContent(ctx, generatedURL, content)
	}
}

func (e *Engine) processSourceMapContent(ctx context.Context, generatedURL string, content []byte) {
	if !e.config.JSTangle.SourceMaps {
		return
	}
	document, err := sourcemap.Parse(content, generatedURL)
	if err != nil {
		logger.Debug("Rejected source map", zap.String("generated_url", generatedURL), zap.Error(err))
		return
	}

	// Follow what the map itself points at before mining its content: an indexed
	// map's external sections, and — when sourcesContent was stripped — the source
	// files themselves, which a deployment that ships the map usually still serves.
	e.queueSourceMapFollowUps(generatedURL, document)

	for _, source := range document.Sources {
		if ctx.Err() != nil {
			return
		}
		virtualURL := generatedURL + "#source=" + url.QueryEscape(source.Path)
		if e.storage != nil {
			if repo := e.storage.Extractions(); repo != nil {
				var sourceNodeID int64
				if generated, parseErr := url.Parse(generatedURL); parseErr == nil {
					sourceNodeID = e.getNodeIDForURL(generated)
				}
				if storeErr := repo.StoreJSTangleSourceArtifact(&storage.JSTangleSourceArtifactModel{
					SourceNodeID: sourceNodeID, SessionID: e.storage.SessionDBID(),
					GeneratedURL: generatedURL, VirtualURL: virtualURL, SourcePath: source.Path,
					Language: source.Language, ContentSHA256: source.ContentSHA256, Content: string(source.Content),
				}); storeErr != nil {
					logger.Debug("Failed to store source-map artifact", zap.String("source", source.Path), zap.Error(storeErr))
				}
			}
		}
		if e.jstangleService == nil {
			continue
		}
		options := e.jsTangleOptions(jstangle.ProfileDiscovery, virtualURL)
		options.Filename = source.Path
		options.MediaType = "application/javascript"
		result, scanErr := e.jstangleService.ScanWithOptions(ctx, source.Content, options)
		if scanErr != nil || result == nil {
			continue
		}
		annotateSourceMappedResult(result, source)
		for i := range result.RequestFacts {
			e.AddRequestFact(virtualURL, result.RequestFacts[i])
		}
		e.processAssetFacts(ctx, virtualURL, source.Content, result.AssetFacts)
		e.processJSTangleCapabilityFacts(virtualURL, result)
		if generated, parseErr := url.Parse(generatedURL); parseErr == nil {
			e.storeJSTangleFactsAtSource(generated, virtualURL, result.RequestFacts)
		}
	}
}

// queueSourceMapFollowUps fetches the further disclosures one map points at: the
// external section maps of an indexed map, and the original source files of a map
// whose sourcesContent was stripped. Both go through the asset graph, so the
// per-parent, per-host and total asset budgets bound the fan-out.
func (e *Engine) queueSourceMapFollowUps(generatedURL string, document *sourcemap.Document) {
	candidates := make([]string, 0, len(document.ExternalSections)+len(document.FetchableSources))
	candidates = append(candidates, document.ExternalSections...)
	candidates = append(candidates, document.FetchableSources...)
	if len(candidates) == 0 {
		return
	}
	graph := e.assetGraph()
	queued := make([]*url.URL, 0, len(candidates))
	for _, candidate := range candidates {
		resolved, added, _ := graph.Add(generatedURL, candidate, AssetSourceMap)
		if !added || resolved == nil {
			continue
		}
		if e.spiderScope == nil || !e.spiderScope.IsInScope(resolved) {
			continue
		}
		queued = append(queued, resolved)
	}
	if len(queued) > 0 {
		logger.Debug("Queued source-map follow-ups",
			zap.String("generated_url", generatedURL), zap.Int("count", len(queued)))
		e.queueJSFetch(queued, ProvenanceReferenced)
	}
}
