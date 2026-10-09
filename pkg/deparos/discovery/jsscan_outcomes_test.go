package discovery

import (
	"context"
	stdhttp "net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/testutil"
	"github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/scope"
)

const testBundle = "https://app.example/assets/app.js"

func outcomeByID(t *testing.T, outcomes []TemplateOutcome) map[string]TemplateOutcome {
	t.Helper()
	byID := make(map[string]TemplateOutcome, len(outcomes))
	for _, o := range outcomes {
		byID[o.Template.ID] = o
	}
	return byID
}

func TestRegistryOutcomesClassifyUnnotedTemplates(t *testing.T) {
	reg := NewRequestTemplateRegistry()
	reg.Add(testBundle, typedFact("claimed", "/api/a", "GET", "high"))
	reg.PendingReplay() // claims "claimed"
	reg.Add(testBundle, typedFact("pending", "/api/b", "GET", "high"))

	got := outcomeByID(t, reg.Outcomes())
	if o := got["pending"]; o.Outcome != TemplateWithheldFlushCap || o.Reason != ReasonUnreplayed {
		t.Fatalf("never-claimed template = %s/%s, want withheld_flush_cap/unreplayed", o.Outcome, o.Reason)
	}
	if o := got["claimed"]; o.Outcome != TemplateUnresolvable {
		t.Fatalf("claimed-but-unnoted template = %s, want unresolvable", o.Outcome)
	}
}

func TestRegistryNoteOutcomeKeepsStrongestObservation(t *testing.T) {
	reg := NewRequestTemplateRegistry()
	reg.Add(testBundle, typedFact("t", "/api/a", "GET", "high"))

	reg.NoteOutcome(testBundle, "t", ReplayNote{Outcome: TemplateDeduped})
	reg.NoteOutcome(testBundle, "t", ReplayNote{Outcome: TemplateReplayedNotFound, Status: 404})
	reg.NoteOutcome(testBundle, "t", ReplayNote{Outcome: TemplateOutOfScope})
	if o := outcomeByID(t, reg.Outcomes())["t"]; o.Outcome != TemplateReplayedNotFound || o.Status != 404 {
		t.Fatalf("got %s/%d, want replayed_not_found/404", o.Outcome, o.Status)
	}
	// A 405 on another variant says more than the 404.
	reg.NoteOutcome(testBundle, "t", ReplayNote{Outcome: TemplateReplayedNotFound, Status: 405})
	if o := outcomeByID(t, reg.Outcomes())["t"]; o.Status != 405 {
		t.Fatalf("status = %d, want 405 to supersede 404", o.Status)
	}
	reg.NoteOutcome(testBundle, "t", ReplayNote{Outcome: TemplateReplayedFound, Status: 200})
	if o := outcomeByID(t, reg.Outcomes())["t"]; o.Outcome != TemplateReplayedFound {
		t.Fatalf("got %s, want replayed_found to win", o.Outcome)
	}
	if reg.NoteOutcome(testBundle, "unknown", ReplayNote{Outcome: TemplateDeduped}) {
		t.Fatal("noting an unknown template must report false")
	}
}

func TestPendingRequestTemplatesNotesWithheldReasons(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Target.StartURL = "https://app.example/"
	e := &Engine{config: cfg}

	post := typedFact("post", "/api/v2/orders", "POST", "high")
	gql := typedFact("gql", "/graphql", "POST", "high")
	gql.Client, gql.OperationType = "graphql", "mutation"
	for _, fact := range []jstangle.HTTPRequestFact{
		typedFact("get", "/api/v2/items", "GET", "high"),
		typedFact("medium", "/api/v2/config", "GET", "medium"),
		typedFact("low", "/api/v2/hint", "GET", "low"),
		post, gql,
	} {
		e.templateRegistry().Add(testBundle, fact)
	}

	pending := e.PendingRequestTemplates()
	if len(pending) != 1 || pending[0].ID != "get" {
		t.Fatalf("replayable templates = %v, want only the high-confidence GET", pending)
	}

	got := outcomeByID(t, e.RequestTemplateOutcomes())
	want := map[string][2]string{
		"medium": {TemplateWithheldConfidence, "medium"},
		"low":    {TemplateWithheldConfidence, "low"},
		"post":   {TemplateWithheldPolicy, "method:POST"},
		"gql":    {TemplateWithheldPolicy, "graphql-mutation"},
	}
	for id, w := range want {
		if o := got[id]; o.Outcome != w[0] || o.Reason != w[1] {
			t.Errorf("%s: got %s/%s, want %s/%s", id, o.Outcome, o.Reason, w[0], w[1])
		}
	}
}

func TestRequestTemplateOutcomesReplayOffAndScope(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Target.StartURL = "https://app.example/"
	cfg.JSTangle.ReplayMode = "off"
	e := &Engine{config: cfg, spiderScope: scope.NewChecker(scope.Config{TargetHost: "app.example", Mode: scope.Mode("subdomain")})}
	e.templateRegistry().Add(testBundle, typedFact("local", "/api/x", "GET", "high"))
	e.templateRegistry().Add(testBundle, typedFact("thirdparty", "https://api.thirdparty.example/v1", "POST", "high"))

	if pending := e.PendingRequestTemplates(); pending != nil {
		t.Fatalf("replay_mode off must replay nothing, got %v", pending)
	}
	got := outcomeByID(t, e.RequestTemplateOutcomes())
	if o := got["local"]; o.Outcome != TemplateWithheldPolicy || o.Reason != "replay-off" {
		t.Fatalf("local = %s/%s, want withheld_policy/replay-off", o.Outcome, o.Reason)
	}
	// A template that was never sent is still checked against the crawl scope.
	if o := got["thirdparty"]; o.Outcome != TemplateOutOfScope || o.Reason != TemplateWithheldPolicy {
		t.Fatalf("thirdparty = %s/%s, want out_of_scope/withheld_policy", o.Outcome, o.Reason)
	}
}

func TestBuildTemplateStubRendersSafeRequest(t *testing.T) {
	fact := typedFact("orders", "/api/v2/orders", "POST", "high")
	fact.Query = []jstangle.FieldTemplate{{
		Name:  jstangle.ValueTemplate{Rendered: "tenant", Static: true},
		Value: jstangle.ValueTemplate{Rendered: "${tenantId}"},
	}}
	fact.Headers = []jstangle.HeaderTemplate{
		{Name: jstangle.ValueTemplate{Rendered: "X-Requested-With", Static: true}, Value: jstangle.ValueTemplate{Rendered: "XMLHttpRequest", Static: true}},
		{Name: jstangle.ValueTemplate{Rendered: "Authorization", Static: true}, Value: jstangle.ValueTemplate{Rendered: "Bearer abc", Static: true}},
		{Name: jstangle.ValueTemplate{Rendered: "Origin", Static: true}, Value: jstangle.ValueTemplate{Rendered: "https://x", Static: true}},
	}
	fact.Body = &jstangle.BodyTemplate{Kind: "json", ContentType: "application/json",
		Value: jstangle.ValueTemplate{Rendered: `{"sku":"${sku}"}`}}

	stub, ok := BuildTemplateStub(ExtractedRequestTemplate{ID: "orders", SourceURL: testBundle, Request: fact}, nil)
	if !ok {
		t.Fatal("expected a stub")
	}
	if stub.Method != "POST" || stub.MethodUnresolved {
		t.Errorf("method = %s (unresolved %v)", stub.Method, stub.MethodUnresolved)
	}
	if !strings.HasPrefix(stub.URL, "https://app.example/api/v2/orders?tenant=") {
		t.Errorf("url = %s", stub.URL)
	}
	if len(stub.Headers) != 1 || stub.Headers[0] != "X-Requested-With: XMLHttpRequest" {
		t.Errorf("headers = %v, want only the safe header", stub.Headers)
	}
	if strings.Contains(stub.Body, "${") || stub.ContentType != "application/json" {
		t.Errorf("body = %q content-type = %q", stub.Body, stub.ContentType)
	}

	unresolved := typedFact("m", "/api/x", "${method}", "high")
	stub, ok = BuildTemplateStub(ExtractedRequestTemplate{ID: "m", SourceURL: testBundle, Request: unresolved}, nil)
	if !ok || stub.Method != "GET" || !stub.MethodUnresolved {
		t.Errorf("templated method: got %s unresolved=%v ok=%v", stub.Method, stub.MethodUnresolved, ok)
	}
	if _, ok := BuildTemplateStub(ExtractedRequestTemplate{ID: "v", Request: typedFact("v", "${base}/x", "GET", "high")}, nil); ok {
		t.Error("a variable-led URL with no alternative must not produce a stub")
	}
}

// TestCoordinatorNotesNotFoundReplay is the coordinator half of D1: a replay the
// Analyzer rejects (404) used to leave nothing behind. It must now be noted as
// replayed_not_found with the status and the captured response.
func TestCoordinatorNotesNotFoundReplay(t *testing.T) {
	reg := NewRequestTemplateRegistry()
	reg.Add(testBundle, typedFact("missing", "/api/v2/items", "GET", "high"))
	reg.Add(testBundle, typedFact("present", "/api/v2/users", "GET", "high"))

	client := testutil.NewMockHTTPClient()
	client.ResponseFunc = func(req *stdhttp.Request) (*responsechain.ResponseChain, error) {
		if strings.HasSuffix(req.URL.Path, "/users") {
			return testutil.NewMockResponseChain(200, `[{"id":1}]`), nil
		}
		return testutil.NewMockResponseChain(404, "no such route"), nil
	}
	reqCache, _ := reqcache.NewHMapCache(&reqcache.Config{Cleanup: true})
	cb := &Callbacks{
		HTTPClient:   client,
		Analyzer:     http.NewAnalyzer(nil),
		RequestCache: reqCache,
		NoteReplayOutcome: func(sourceURL, templateID string, note ReplayNote) {
			reg.NoteOutcome(sourceURL, templateID, note)
		},
	}
	coordinator := NewPayloadCoordinator(queue.New(), 1, cb)
	dir, _ := url.Parse("https://app.example/")
	task := NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{DirURL: dir, GetRequestTemplates: reg.PendingReplay})
	coordinator.executeJSExtractedRequestTask(context.Background(), task)

	got := outcomeByID(t, reg.Outcomes())
	missing := got["missing"]
	if missing.Outcome != TemplateReplayedNotFound || missing.Status != 404 {
		t.Fatalf("missing = %s/%d, want replayed_not_found/404", missing.Outcome, missing.Status)
	}
	if missing.Response == nil || string(missing.Response.Body) != "no such route" {
		t.Fatalf("not-found replay must keep its response evidence, got %+v", missing.Response)
	}
	if missing.Method != "GET" || missing.URL != "https://app.example/api/v2/items" {
		t.Errorf("replayed request = %s %s", missing.Method, missing.URL)
	}
	if present := got["present"]; present.Outcome != TemplateReplayedFound || present.Status != 200 {
		t.Fatalf("present = %s/%d, want replayed_found/200", present.Outcome, present.Status)
	}
}

func TestCollectJSFactsBundlesNonRequestFacts(t *testing.T) {
	e := &Engine{}
	full := &jstangle.ValueTemplate{Rendered: "/admin/users", Static: true}
	result := &jstangle.ScanResult{
		RequestFacts: []jstangle.HTTPRequestFact{
			typedFact("hi", "/api/x", "GET", "high"),
			typedFact("lo", "/api/hint", "GET", "low"),
		},
		ClientRoutes: []jstangle.ClientRouteFact{{Kind: "clientRoute", ID: "r1",
			Path: jstangle.ValueTemplate{Rendered: "users"}, FullPath: full}},
		PathLiterals: []jstangle.PathLiteralFact{{Kind: "pathLiteral", ID: "p1",
			Value: jstangle.ValueTemplate{Rendered: "/internal/metrics", Static: true}}},
		WebSockets: []jstangle.WebSocketFact{{Kind: "websocket", ID: "w1"}},
	}
	e.collectJSFacts(testBundle, result)
	e.collectJSFacts(testBundle, result) // re-analysis of the same asset dedupes
	e.collectJSFacts("https://app.example/empty.js", &jstangle.ScanResult{})

	bundles := e.JSFactBundles()
	if len(bundles) != 1 {
		t.Fatalf("bundles = %d, want 1 (empty assets omitted)", len(bundles))
	}
	b := bundles[0]
	if len(b.ClientRoutes) != 1 || b.ClientRoutes[0].FullPath == nil || b.ClientRoutes[0].FullPath.Rendered != "/admin/users" {
		t.Errorf("client routes = %+v, want fullPath kept", b.ClientRoutes)
	}
	if len(b.PathLiterals) != 1 || len(b.WebSockets) != 1 {
		t.Errorf("path literals %d websockets %d, want 1/1", len(b.PathLiterals), len(b.WebSockets))
	}
	if len(b.RequestHints) != 1 || b.RequestHints[0].ID != "lo" {
		t.Errorf("request hints = %+v, want only the low-confidence fact", b.RequestHints)
	}
}
