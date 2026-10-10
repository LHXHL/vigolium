package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const jsTestBundle = "https://app.example/assets/app.js"

// recordingSaver captures every saved record, remark and artifact so a test
// can assert what a target's JS templates turned into.
type recordingSaver struct {
	mu        sync.Mutex
	next      int
	records   map[string]savedRecord // uuid -> record
	remarks   map[string][]string
	artifacts []capturedArtifact
}

type savedRecord struct {
	source string
	rr     *httpmsg.HttpRequestResponse
}

func newRecordingSaver() *recordingSaver {
	return &recordingSaver{records: map[string]savedRecord{}, remarks: map[string][]string{}}
}

func (s *recordingSaver) SaveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source, project string) (string, error) {
	uuids, err := s.SaveRecordBatch(ctx, []*httpmsg.HttpRequestResponse{rr}, source, project)
	return uuids[0], err
}

func (s *recordingSaver) SaveRecordBatch(_ context.Context, records []*httpmsg.HttpRequestResponse, source, _ string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uuids := make([]string, len(records))
	for i, rr := range records {
		s.next++
		uuids[i] = fmt.Sprintf("rec-%d", s.next)
		s.records[uuids[i]] = savedRecord{source: source, rr: rr}
	}
	return uuids, nil
}

func (s *recordingSaver) SaveAnalysisArtifact(_ context.Context, recordUUID, kind, filename, mediaType, sha256 string, content []byte, metadata string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts = append(s.artifacts, capturedArtifact{
		recordUUID: recordUUID, kind: kind, filename: filename, mediaType: mediaType,
		sha256: sha256, content: append([]byte(nil), content...), metadata: metadata,
	})
	return nil
}

func (s *recordingSaver) AppendRemarks(_ context.Context, annotations map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for uuid, remarks := range annotations {
		s.remarks[uuid] = append(s.remarks[uuid], remarks...)
	}
	return nil
}

// byRequest finds the saved record for "METHOD URL".
func (s *recordingSaver) byRequest(t *testing.T, method, rawURL string) (string, savedRecord) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for uuid, rec := range s.records {
		if rec.rr.Target() == rawURL && strings.EqualFold(rec.rr.Request().Method(), method) {
			return uuid, rec
		}
	}
	return "", savedRecord{}
}

func jsOutcome(id, rawURL, method, confidence, outcome string) discovery.TemplateOutcome {
	fact := jstangle.HTTPRequestFact{
		Kind: "httpRequest", ID: id,
		URL:        jstangle.ValueTemplate{Rendered: rawURL, Static: true},
		Method:     jstangle.ValueTemplate{Rendered: method, Static: true},
		Client:     "fetch",
		Provenance: jstangle.Provenance{Extractor: "fetch", Confidence: confidence, Start: &jstangle.SourceLocation{Line: 42}},
	}
	return discovery.TemplateOutcome{
		Template:   discovery.ExtractedRequestTemplate{ID: id, SourceURL: jsTestBundle, Request: fact, Confidence: confidence},
		ReplayNote: discovery.ReplayNote{Outcome: outcome},
	}
}

func replayed(o discovery.TemplateOutcome, status int, body string) discovery.TemplateOutcome {
	o.Status = status
	o.Method = strings.ToUpper(o.Template.Request.Method.Rendered)
	o.URL = "https://app.example" + o.Template.Request.URL.Rendered
	if o.Outcome == discovery.TemplateReplayedNotFound {
		o.Response = &deparosstorage.ResponseData{
			StatusCode: status, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(body),
		}
	}
	return o
}

func mustRR(t *testing.T, method, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURLWithMethod(rawURL, method, nil, nil)
	require.NoError(t, err)
	return rr
}

// jsFixture is one target's worth of JS template outcomes covering every
// persistence branch, plus the crawl records they relate to.
type jsFixture struct {
	outcomes []discovery.TemplateOutcome
	nodes    *nodeIndex
	crawl    map[string][]*httpmsg.HttpRequestResponse
	order    []string
}

func newJSFixture(t *testing.T) jsFixture {
	t.Helper()
	orders := jsOutcome("orders", "/api/v2/orders", "POST", "high", discovery.TemplateWithheldPolicy)
	orders.Reason = "method:POST"
	orders.Template.Request.Headers = []jstangle.HeaderTemplate{
		{Name: jstangle.ValueTemplate{Rendered: "X-Requested-With", Static: true}, Value: jstangle.ValueTemplate{Rendered: "XMLHttpRequest", Static: true}},
		{Name: jstangle.ValueTemplate{Rendered: "Authorization", Static: true}, Value: jstangle.ValueTemplate{Rendered: "Bearer leaked", Static: true}},
	}
	orders.Template.Request.Body = &jstangle.BodyTemplate{Kind: "json", ContentType: "application/json",
		Value: jstangle.ValueTemplate{Rendered: `{"sku":"${sku}","qty":1}`}}
	orders.Template.Request.Auth = &jstangle.AuthContext{Kind: "bearer", Source: "localStorage:jwt", SourceKind: "localStorage"}

	cfgMedium := jsOutcome("config", "/api/v2/config", "GET", "medium", discovery.TemplateWithheldConfidence)
	cfgMedium.Reason = "medium"

	usersURL := "https://app.example/api/v2/users"
	users := mustRR(t, "GET", usersURL)
	bundle := mustRR(t, "GET", jsTestBundle)
	nodes := newNodeIndex(4)
	nodes.add("GET", usersURL, users.Target())
	nodes.add("GET", jsTestBundle, bundle.Target())

	return jsFixture{
		outcomes: []discovery.TemplateOutcome{
			replayed(jsOutcome("users", "/api/v2/users", "GET", "high", discovery.TemplateReplayedFound), 200, ""),
			replayed(jsOutcome("items", "/api/v2/items", "GET", "high", discovery.TemplateReplayedNotFound), 404, `{"error":"not found"}`),
			replayed(jsOutcome("upload", "/api/v2/upload", "GET", "high", discovery.TemplateReplayedNotFound), 405, `{"error":"use POST"}`),
			orders,
			cfgMedium,
			jsOutcome("offsite", "https://other.example/x", "GET", "high", discovery.TemplateOutOfScope),
			jsOutcome("hint", "/api/v2/hint", "GET", "low", discovery.TemplateWithheldConfidence),
		},
		nodes: nodes,
		crawl: map[string][]*httpmsg.HttpRequestResponse{
			crawlRecordSource:    {bundle},
			jstangleRecordSource: {users},
		},
		order: []string{crawlRecordSource, jstangleRecordSource},
	}
}

func drainItems(d *DeparosDiscoverySource) []string {
	var emitted []string
	for {
		select {
		case item := <-d.items:
			emitted = append(emitted, item.Request.Request().Method()+" "+item.Request.Target())
		default:
			return emitted
		}
	}
}

// TestJSTangleFactAlwaysPersisted is D1's contract: every in-scope,
// non-hint JS template survives the target as an http_records row with
// jstangle:* remarks and its fact attached; only found templates and
// not-found replays with an "exists" status are emitted.
func TestJSTangleFactAlwaysPersisted(t *testing.T) {
	saver := newRecordingSaver()
	d := newTestDiscoverySource(saver)
	fx := newJSFixture(t)
	fallback, _ := url.Parse("https://app.example/")

	plan := planJSTemplates(fx.outcomes, fx.nodes, fallback, JSTemplatePersistConfig{})
	plan.bundles = []discovery.JSFactBundle{
		{SourceURL: jsTestBundle, ClientRoutes: []jstangle.ClientRouteFact{{Kind: "clientRoute", ID: "r1",
			FullPath: &jstangle.ValueTemplate{Rendered: "/admin/users", Static: true}}}},
		// Inline script with no record of its own: anchored to the origin.
		{SourceURL: "https://app.example/#inline-1", PathLiterals: []jstangle.PathLiteralFact{{Kind: "pathLiteral", ID: "p1",
			Value: jstangle.ValueTemplate{Rendered: "/internal/metrics", Static: true}}}},
	}

	acc := newImportAccum(8)
	err := d.importCollected(context.Background(), nil, collectedGroups{
		sourceOrder: fx.order, bySource: fx.crawl, jsTemplates: plan, acc: acc,
	})
	require.NoError(t, err)
	d.noteJSTemplateStats("https://app.example/", plan, acc.factBundles)

	// Persisted stubs: the two not-found replays and the two withheld templates.
	for _, req := range [][2]string{
		{"GET", "https://app.example/api/v2/items"},
		{"GET", "https://app.example/api/v2/upload"},
		{"POST", "https://app.example/api/v2/orders"},
		{"GET", "https://app.example/api/v2/config"},
	} {
		uuid, rec := saver.byRequest(t, req[0], req[1])
		require.NotEmptyf(t, uuid, "%s %s must be persisted", req[0], req[1])
		assert.Equalf(t, jstangleRecordSource, rec.source, "%s must be stored under source=jstangle", req[1])
	}
	for _, rawURL := range []string{"https://other.example/x", "https://app.example/api/v2/hint"} {
		uuid, _ := saver.byRequest(t, "GET", rawURL)
		assert.Emptyf(t, uuid, "%s must not be persisted (out of scope / low-confidence hint)", rawURL)
	}

	// The not-found replay carries its response; the withheld POST carries none,
	// but keeps its templated body and only the safe header.
	_, items := saver.byRequest(t, "GET", "https://app.example/api/v2/items")
	require.NotNil(t, items.rr.Response(), "a not-found replay must keep its response evidence")
	assert.Equal(t, 404, items.rr.Response().StatusCode())
	ordersUUID, orders := saver.byRequest(t, "POST", "https://app.example/api/v2/orders")
	assert.Nil(t, orders.rr.Response(), "a withheld template was never sent, so it has no response")
	raw := string(orders.rr.Request().Raw())
	assert.Contains(t, raw, "X-Requested-With: XMLHttpRequest")
	assert.NotContains(t, raw, "Bearer leaked", "sensitive header literals must never be stored")
	assert.Contains(t, raw, `"qty":1`)
	assert.NotContains(t, raw, "${sku}", "body variables are rendered as replay renders them")

	// Remarks.
	assert.Subset(t, saver.remarks[ordersUUID], []string{
		"jstangle:withheld_policy", "jstangle:reason=method:POST", "jstangle:confidence=high",
		"jstangle:extractor=fetch", "jstangle:src=" + jsTestBundle + "#L42",
		"jstangle:auth=bearer:localStorage:jwt",
	})
	usersUUID, _ := saver.byRequest(t, "GET", "https://app.example/api/v2/users")
	assert.Contains(t, saver.remarks[usersUUID], "jstangle:replayed_found",
		"a found template annotates the node the crawl imported instead of writing a second row")

	// Emission: the found template's node (as before) and the 405, nothing else.
	emitted := drainItems(d)
	assert.ElementsMatch(t, []string{
		"GET " + jsTestBundle,
		"GET https://app.example/api/v2/users",
		"GET https://app.example/api/v2/upload",
	}, emitted)

	// Artifacts: one jstangle-fact per template record, one jstangle-facts per asset.
	factKinds := map[string]int{}
	for _, a := range saver.artifacts {
		factKinds[a.kind]++
	}
	assert.Equal(t, 5, factKinds[jstangleFactArtifactKind], "users, items, upload, orders, config")
	assert.Equal(t, 2, factKinds[jstangleFactsArtifactKind])
	bundleUUID, _ := saver.byRequest(t, "GET", jsTestBundle)
	for _, a := range saver.artifacts {
		if a.kind != jstangleFactsArtifactKind {
			continue
		}
		var doc struct {
			SourceURL string `json:"source_url"`
		}
		require.NoError(t, json.Unmarshal(a.content, &doc))
		if doc.SourceURL == jsTestBundle {
			assert.Equal(t, bundleUUID, a.recordUUID, "an asset's facts anchor to the asset's own record")
		} else {
			assert.NotEmpty(t, a.recordUUID, "an unrecorded script's facts anchor to its origin's record")
		}
	}

	stats := d.Stats()
	assert.Equal(t, 4, stats.JSFactsPersisted)
	assert.Equal(t, 2, stats.JSFactsNotFound)
	assert.Equal(t, map[string]int{
		discovery.TemplateWithheldPolicy: 1, discovery.TemplateWithheldConfidence: 2,
	}, stats.JSFactsWithheld)
	assert.Equal(t, 2, stats.JSFactBundles)
	assert.Zero(t, stats.JSTemplatesCapped)
}

func TestPlanJSTemplatesCapKeepsEmittedFirst(t *testing.T) {
	fx := newJSFixture(t)
	plan := planJSTemplates(fx.outcomes, fx.nodes, nil, JSTemplatePersistConfig{MaxPerTarget: 2})
	assert.Equal(t, 2, plan.capped)
	require.Len(t, plan.emit, 1)
	assert.Equal(t, "upload", plan.emit[0].outcome.Template.ID, "the emitted 405 outranks persist-only stubs")
	require.Len(t, plan.persist, 1)
	assert.Equal(t, "items", plan.persist[0].outcome.Template.ID, "a not-found replay outranks withheld ones")
}

func TestPlanJSTemplatesConfig(t *testing.T) {
	fx := newJSFixture(t)

	plan := planJSTemplates(fx.outcomes, fx.nodes, nil, JSTemplatePersistConfig{SkipUnreplayed: true})
	ids := func(records []*jsTemplateRecord) []string {
		var out []string
		for _, r := range records {
			out = append(out, r.outcome.Template.ID)
		}
		slices.Sort(out)
		return out
	}
	assert.Equal(t, []string{"items"}, ids(plan.persist), "persist_unreplayed=false keeps only replayed stubs")
	assert.Equal(t, []string{"upload"}, ids(plan.emit))

	plan = planJSTemplates(fx.outcomes, fx.nodes, nil, JSTemplatePersistConfig{EmitStatuses: []int{}})
	assert.Empty(t, plan.emit, "an empty emit list makes every not-found replay persist-only")

	plan = planJSTemplates(fx.outcomes, fx.nodes, nil, JSTemplatePersistConfig{EmitStatuses: []int{404, 405}})
	assert.Equal(t, []string{"items", "upload"}, ids(plan.emit))
}

// TestJSTemplateStubsSurviveDeparosCleanup runs the post-discovery cleanup
// passes against a real database: they are scoped to source='deparos', so the
// jstangle stubs (4xx, and request-only) must all survive while deparos 4xx
// noise is removed.
func TestJSTemplateStubsSurviveDeparosCleanup(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "d1.sqlite")
	db, err := database.NewDB(&config.DatabaseConfig{Enabled: true, Driver: "sqlite", SQLite: config.SQLiteConfig{
		Path: dbPath, BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL", CacheSize: 1000,
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close(); _ = os.Remove(dbPath) })
	require.NoError(t, db.CreateSchema(ctx))
	repo := database.NewRepository(db)

	d := newTestDiscoverySource(repo)
	d.cfg.ProjectUUID = database.DefaultProjectUUID
	fx := newJSFixture(t)
	plan := planJSTemplates(fx.outcomes, fx.nodes, nil, JSTemplatePersistConfig{})

	noiseRaw := httpmsg.BuildRawResponse(404, map[string]string{"Content-Type": "text/html"}, "nope")
	noise := mustRR(t, "GET", "https://app.example/wordlist-guess").WithResponse(httpmsg.NewHttpResponse(noiseRaw))
	fx.crawl[crawlRecordSource] = append(fx.crawl[crawlRecordSource], noise)

	err = d.importCollected(ctx, nil, collectedGroups{
		sourceOrder: fx.order, bySource: fx.crawl, jsTemplates: plan, acc: newImportAccum(8),
	})
	require.NoError(t, err)
	drainItems(d)

	_, err = repo.ApplyDeparosStatusPolicy(ctx, database.DefaultProjectUUID, database.DeparosStatusPolicy{})
	require.NoError(t, err)
	_, err = repo.DeduplicateDeparosByNormHash(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	_, err = repo.DeduplicateSoftDeparosRecords(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	_, err = repo.DeduplicateDeparosRecords(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)

	var rows []database.HTTPRecord
	require.NoError(t, db.NewSelect().Model(&rows).Where("source = ?", jstangleRecordSource).Scan(ctx))
	got := map[string][]string{}
	for _, row := range rows {
		got[row.Method+" "+row.Path] = row.Remarks
	}
	for _, key := range []string{
		"GET /api/v2/items", "GET /api/v2/upload", "POST /api/v2/orders", "GET /api/v2/config", "GET /api/v2/users",
	} {
		require.Containsf(t, got, key, "jstangle record %s must survive the deparos cleanup", key)
	}
	assert.Contains(t, got["GET /api/v2/items"], "jstangle:replayed_not_found")
	assert.Contains(t, got["POST /api/v2/orders"], "jstangle:auth=bearer:localStorage:jwt")

	var noiseLeft int
	require.NoError(t, db.NewRaw("SELECT COUNT(*) FROM http_records WHERE source = 'deparos' AND path = '/wordlist-guess'").Scan(ctx, &noiseLeft))
	assert.Zero(t, noiseLeft, "the cleanup did run: deparos 4xx noise is gone")
}
