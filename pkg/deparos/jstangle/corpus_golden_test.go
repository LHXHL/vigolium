package jstangle

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The corpus golden is the cross-language contract between the TypeScript
// helper and its Go consumers. It runs the real embedded helper over every
// file in test/testdata/js-corpus with the full profile and compares a
// normalized projection (no ids, spans or timings) with
// testdata/corpus/<name>.golden.json.
//
// Regenerate after an intended helper change (the host helper must be fresh,
// see `make ensure-jstangle`):
//
//	go test ./pkg/deparos/jstangle -run TestCorpusGolden -update
var updateCorpusGolden = flag.Bool("update", false, "rewrite jstangle corpus golden files")

const (
	corpusDir       = "../../../test/testdata/js-corpus"
	corpusGoldenDir = "testdata/corpus"
	// A kind with more records than this is summarized by its count only, so
	// the request-cap file does not produce a thousand-line golden.
	corpusListLimit = 50
)

type corpusFact struct {
	Kind       string   `json:"kind"`
	URL        string   `json:"url,omitempty"`
	FullPath   string   `json:"fullPath,omitempty"`
	Method     string   `json:"method,omitempty"`
	Query      []string `json:"query,omitempty"`
	BodyKind   string   `json:"bodyKind,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	AssetType  string   `json:"assetType,omitempty"`
	Loader     string   `json:"loader,omitempty"`
	// Alternatives are the concrete URLs of an enumerated template asset.
	Alternatives []string `json:"alternatives,omitempty"`
	Auth         string   `json:"auth,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Key          string   `json:"key,omitempty"`
	Suppressed   []string `json:"suppressed,omitempty"`
	Operation    string   `json:"operation,omitempty"`
	Flow         string   `json:"flow,omitempty"`
}

type corpusGolden struct {
	Status     string         `json:"status"`
	ReasonCode string         `json:"reasonCode,omitempty"`
	Truncated  map[string]int `json:"truncated,omitempty"`
	Counts     map[string]int `json:"counts"`
	Facts      []corpusFact   `json:"facts"`
}

func requestProjection(fact *HTTPRequestFact) corpusFact {
	out := corpusFact{
		Kind: fact.Kind, URL: fact.URL.Rendered, Method: fact.Method.Rendered,
		Confidence: fact.Provenance.Confidence,
	}
	for _, field := range fact.Query {
		out.Query = append(out.Query, field.Name.Rendered)
	}
	if fact.Body != nil {
		out.BodyKind = fact.Body.Kind
	}
	if fact.Auth != nil {
		out.Auth = fact.Auth.Kind + ":" + fact.Auth.Source
	}
	for _, suppressed := range fact.Suppressed {
		out.Suppressed = append(out.Suppressed, suppressed.Reason+":"+suppressed.URL)
	}
	sort.Strings(out.Suppressed)
	return out
}

func projectCorpusResult(result *ScanResult) corpusGolden {
	golden := corpusGolden{Status: result.Status(), Counts: map[string]int{}}
	if result.Completion != nil {
		golden.ReasonCode = result.Completion.ReasonCode
		golden.Truncated = result.Completion.Counts.Truncated
	}
	var facts []corpusFact
	add := func(kind string, projected []corpusFact) {
		if len(projected) == 0 {
			return
		}
		golden.Counts[kind] = len(projected)
		if len(projected) <= corpusListLimit {
			facts = append(facts, projected...)
		}
	}

	var requests []corpusFact
	for i := range result.RequestFacts {
		requests = append(requests, requestProjection(&result.RequestFacts[i]))
	}
	add("httpRequest", requests)

	var assets []corpusFact
	for _, fact := range result.AssetFacts {
		assets = append(assets, corpusFact{
			Kind: fact.Kind, URL: fact.URL.Rendered, AssetType: fact.AssetType,
			Loader: fact.Loader, Alternatives: fact.URL.Alternatives, Confidence: fact.Provenance.Confidence,
		})
	}
	add("assetReference", assets)

	var routes []corpusFact
	for _, fact := range result.ClientRoutes {
		projected := corpusFact{Kind: fact.Kind, URL: fact.Path.Rendered, Confidence: fact.Provenance.Confidence}
		if fact.FullPath != nil {
			projected.FullPath = fact.FullPath.Rendered
		}
		routes = append(routes, projected)
	}
	add("clientRoute", routes)

	var literals []corpusFact
	for _, fact := range result.PathLiterals {
		literals = append(literals, corpusFact{
			Kind: fact.Kind, URL: fact.Value.Rendered, Reason: fact.Reason, Key: fact.Key,
			Confidence: fact.Provenance.Confidence,
		})
	}
	add("pathLiteral", literals)

	var graphql []corpusFact
	for _, fact := range result.GraphQLOperations {
		projected := corpusFact{
			Kind: fact.Kind, Operation: fact.OperationType + ":" + fact.OperationName,
			Confidence: fact.Provenance.Confidence,
		}
		if fact.Endpoint != nil {
			projected.URL = fact.Endpoint.Rendered
		}
		graphql = append(graphql, projected)
	}
	add("graphqlOperation", graphql)

	var realtime []corpusFact
	for _, fact := range result.WebSockets {
		realtime = append(realtime, corpusFact{Kind: fact.Kind, URL: fact.URL.Rendered, Confidence: fact.Provenance.Confidence})
	}
	for _, fact := range result.EventSources {
		realtime = append(realtime, corpusFact{Kind: fact.Kind, URL: fact.URL.Rendered, Confidence: fact.Provenance.Confidence})
	}
	add("realtime", realtime)

	var flows []corpusFact
	for _, fact := range result.DomFlowFacts {
		flows = append(flows, corpusFact{Kind: fact.Kind, Flow: fact.Source + " -> " + fact.Sink, Confidence: fact.Confidence})
	}
	for _, fact := range result.BrowserFlows {
		flows = append(flows, corpusFact{Kind: fact.Kind, Flow: fact.FlowType + ": " + fact.Source + " -> " + fact.Sink, Confidence: fact.Confidence})
	}
	add("flow", flows)

	sort.SliceStable(facts, func(i, j int) bool {
		a, b := facts[i], facts[j]
		for _, pair := range [][2]string{{a.Kind, b.Kind}, {a.URL, b.URL}, {a.Method, b.Method}, {a.FullPath, b.FullPath}, {a.Flow, b.Flow}, {a.Operation, b.Operation}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
	golden.Facts = facts
	if golden.Facts == nil {
		golden.Facts = []corpusFact{}
	}
	return golden
}

func TestCorpusGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus golden runs the real helper; covered by `make test`")
	}
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.js"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files under %s: %v", corpusDir, err)
	}

	service := newScanService(t)
	caps, err := service.Capabilities()
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	// A helper built before this contract cannot match the goldens; that is a
	// stale build, not a regression.
	if !caps.Has(CapabilityPathLiteral) {
		t.Skip("embedded jstangle predates the corpus contract; run `make ensure-jstangle`")
	}

	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".js")
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.ScanWithOptions(context.Background(), content, ScanOptions{
				Profile: ProfileFull, Filename: filepath.Base(file),
				SourceURL: "https://corpus.test/assets/" + filepath.Base(file),
			})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			encoder.SetEscapeHTML(false)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(projectCorpusResult(result)); err != nil {
				t.Fatal(err)
			}
			got := buffer.Bytes()
			goldenPath := filepath.Join(corpusGoldenDir, name+".golden.json")
			if *updateCorpusGolden {
				if err := os.MkdirAll(corpusGoldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("missing golden %s (run with -update): %v", goldenPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("corpus projection drifted for %s (run with -update after an intended change)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
			}
		})
	}
}
