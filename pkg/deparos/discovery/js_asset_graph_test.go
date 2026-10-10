package discovery

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/sourcemap"
)

func TestJSAssetGraphResolvesAndTerminatesCycles(t *testing.T) {
	graph := NewJSAssetGraph(JSAssetGraphConfig{MaxDepth: 3, MaxAssetsPerParent: 4, MaxAssetsPerHost: 10, MaxAssetsTotal: 20})
	graph.AddRoot("https://example.com/assets/app.js", AssetScript)
	chunk, added, reason := graph.Add("https://example.com/assets/app.js", "./chunks/lazy.js", AssetDynamicImport)
	if !added || reason != "" || chunk.String() != "https://example.com/assets/chunks/lazy.js" {
		t.Fatalf("unexpected resolved chunk: %v added=%v reason=%s", chunk, added, reason)
	}
	worker, added, _ := graph.Add(chunk.String(), "../worker.js", AssetWorker)
	if !added || worker.String() != "https://example.com/assets/worker.js" {
		t.Fatalf("unexpected worker edge: %v", worker)
	}
	if _, added, reason := graph.Add(worker.String(), "./chunks/lazy.js", AssetDynamicImport); added || reason != "duplicate-url" {
		t.Fatalf("cycle was not terminated: added=%v reason=%s", added, reason)
	}
	if nodes := graph.Nodes(); len(nodes) != 3 {
		t.Fatalf("graph nodes = %d, want 3: %+v", len(nodes), nodes)
	}
}

func TestJSAssetGraphEnforcesParentAndDepthCaps(t *testing.T) {
	graph := NewJSAssetGraph(JSAssetGraphConfig{MaxDepth: 1, MaxAssetsPerParent: 1, MaxAssetsPerHost: 10, MaxAssetsTotal: 10})
	graph.AddRoot("https://example.com/app.js", AssetScript)
	first, added, _ := graph.Add("https://example.com/app.js", "/one.js", AssetScript)
	if !added {
		t.Fatal("first child rejected")
	}
	if _, added, reason := graph.Add("https://example.com/app.js", "/two.js", AssetScript); added || reason != "parent-limit" {
		t.Fatalf("parent cap: added=%v reason=%s", added, reason)
	}
	if _, added, reason := graph.Add(first.String(), "/deep.js", AssetScript); added || reason != "depth-limit" {
		t.Fatalf("depth cap: added=%v reason=%s", added, reason)
	}
}

// Parsing, path sanitization, indexed maps and inline references are covered by
// the parser's own tests in pkg/deparos/jstangle/sourcemap; this package
// tests only how discovery wires that parser in.

func TestAnnotateSourceMappedResultCoversEveryTypedFactFamily(t *testing.T) {
	provenance := jstangle.Provenance{Extractor: "fixture", Confidence: "high"}
	result := &jstangle.ScanResult{
		RequestFacts:      []jstangle.HTTPRequestFact{{Provenance: provenance}},
		DomFlowFacts:      []jstangle.DomFlowFact{{Provenance: provenance}},
		AssetFacts:        []jstangle.AssetReferenceFact{{Provenance: provenance}},
		GraphQLOperations: []jstangle.GraphQLOperationFact{{Provenance: provenance}},
		WebSockets:        []jstangle.WebSocketFact{{Provenance: provenance}},
		EventSources:      []jstangle.EventSourceFact{{Provenance: provenance}},
		ClientRoutes:      []jstangle.ClientRouteFact{{Provenance: provenance}},
		BrowserFlows:      []jstangle.BrowserSecurityFlowFact{{Provenance: provenance}},
	}
	source := sourcemap.OriginalSource{
		Path: "src/api.ts", GeneratedSourceURL: "https://example.test/assets/app.js",
	}

	annotateSourceMappedResult(result, source)
	assertMapped := func(name string, got jstangle.Provenance) {
		t.Helper()
		if got.ModulePath != source.Path || len(got.ResolutionSteps) != 1 {
			t.Fatalf("%s provenance not mapped: %#v", name, got)
		}
		step := got.ResolutionSteps[0]
		if step.Kind != "source-map" || step.Name != source.Path || step.Value != source.GeneratedSourceURL {
			t.Fatalf("%s source-map step = %#v", name, step)
		}
	}
	assertMapped("http", result.RequestFacts[0].Provenance)
	assertMapped("dom", result.DomFlowFacts[0].Provenance)
	assertMapped("asset", result.AssetFacts[0].Provenance)
	assertMapped("graphql", result.GraphQLOperations[0].Provenance)
	assertMapped("websocket", result.WebSockets[0].Provenance)
	assertMapped("sse", result.EventSources[0].Provenance)
	assertMapped("route", result.ClientRoutes[0].Provenance)
	assertMapped("browser", result.BrowserFlows[0].Provenance)

	annotateSourceMappedResult(result, source)
	if len(result.RequestFacts[0].Provenance.ResolutionSteps) != 1 {
		t.Fatal("source-map annotation was not idempotent")
	}
}

// A chunk runtime names far more children than MaxAssetsPerParent allows; the
// loader budget admits them without eating the general per-parent slots, and
// per-host/total caps still bound the whole graph.
func TestJSAssetGraphLoaderChunkBudget(t *testing.T) {
	const parent = "https://example.com/static/js/main.js"
	graph := NewJSAssetGraph(JSAssetGraphConfig{
		MaxDepth: 4, MaxAssetsPerParent: 2, MaxChunksPerRuntime: 5, MaxAssetsPerHost: 100, MaxAssetsTotal: 100,
	})
	graph.AddRoot(parent, AssetScript)
	for i := 0; i < 5; i++ {
		if _, added, reason := graph.AddLoaded(parent, fmt.Sprintf("/static/js/%d.chunk.js", i), AssetChunk, jstangle.LoaderWebpackChunk); !added {
			t.Fatalf("chunk %d rejected: %s", i, reason)
		}
	}
	if _, added, reason := graph.AddLoaded(parent, "/static/js/99.chunk.js", AssetChunk, jstangle.LoaderWebpackChunk); added || reason != "chunk-limit" {
		t.Fatalf("chunk budget: added=%v reason=%s", added, reason)
	}
	// Plain references keep their own MaxAssetsPerParent slots.
	for _, child := range []string{"/a.js", "/b.js"} {
		if _, added, reason := graph.Add(parent, child, AssetScript); !added {
			t.Fatalf("plain child %s rejected: %s", child, reason)
		}
	}
	if _, added, reason := graph.Add(parent, "/c.js", AssetScript); added || reason != "parent-limit" {
		t.Fatalf("parent cap: added=%v reason=%s", added, reason)
	}

	// Host and total caps still bound loader children.
	small := NewJSAssetGraph(JSAssetGraphConfig{MaxDepth: 4, MaxAssetsPerParent: 1, MaxChunksPerRuntime: 50, MaxAssetsPerHost: 3, MaxAssetsTotal: 100})
	small.AddRoot(parent, AssetScript)
	for i := 0; i < 2; i++ {
		if _, added, _ := small.AddLoaded(parent, fmt.Sprintf("/%d.js", i), AssetChunk, jstangle.LoaderWebpackChunk); !added {
			t.Fatalf("chunk %d rejected under host cap", i)
		}
	}
	if _, added, reason := small.AddLoaded(parent, "/9.js", AssetChunk, jstangle.LoaderWebpackChunk); added || reason != "host-limit" {
		t.Fatalf("host cap: added=%v reason=%s", added, reason)
	}
}

func TestDefaultJSAssetGraphChunkBudget(t *testing.T) {
	if got := NewJSAssetGraph(JSAssetGraphConfig{}).config.MaxChunksPerRuntime; got != 512 {
		t.Fatalf("default MaxChunksPerRuntime = %d, want 512", got)
	}
}

func TestAssetFactURLsAndFetchability(t *testing.T) {
	static := jstangle.AssetReferenceFact{AssetType: string(AssetChunk), Loader: jstangle.LoaderWebpackChunk,
		URL: jstangle.ValueTemplate{Rendered: "/static/js/17.abc.chunk.js", Static: true}}
	if got := assetFactURLs(static); len(got) != 1 || got[0] != "/static/js/17.abc.chunk.js" {
		t.Fatalf("static fact urls = %v", got)
	}
	enumerated := jstangle.AssetReferenceFact{AssetType: string(AssetDynamicImport), Loader: jstangle.LoaderTemplateImport,
		URL: jstangle.ValueTemplate{Rendered: "./locales/${lang}.js", Alternatives: []string{"./locales/en.js", "./locales/${x}.js", "./locales/fr.js"}}}
	if got := assetFactURLs(enumerated); len(got) != 2 || got[0] != "./locales/en.js" || got[1] != "./locales/fr.js" {
		t.Fatalf("enumerated template urls = %v", got)
	}
	hint := jstangle.AssetReferenceFact{AssetType: string(AssetDynamicImport), URL: jstangle.ValueTemplate{Rendered: "./pages/${name}.js"}}
	if got := assetFactURLs(hint); len(got) != 0 {
		t.Fatalf("template hint should yield no urls, got %v", got)
	}

	js, _ := url.Parse("https://example.com/static/js/17.abc.chunk.js")
	css, _ := url.Parse("https://example.com/assets/About-C2y.css")
	if !assetFetchable(static, js) {
		t.Fatal("webpack JS chunk should be fetched")
	}
	if assetFetchable(jstangle.AssetReferenceFact{AssetType: string(AssetChunk), Loader: jstangle.LoaderWebpackCSSChunk}, css) {
		t.Fatal("webpack CSS chunk should stay a graph node")
	}
	if assetFetchable(jstangle.AssetReferenceFact{AssetType: string(AssetChunk), Loader: jstangle.LoaderVitePreload}, css) {
		t.Fatal("Vite CSS preload dep should stay a graph node")
	}
	if assetFetchable(jstangle.AssetReferenceFact{AssetType: string(AssetWASM)}, js) {
		t.Fatal("wasm should stay a graph node")
	}
}
