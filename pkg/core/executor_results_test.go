package core

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/work"
)

// metaStub is an activeStub with a configurable static Description (the
// "what it means / how it's exploited / fix" explanation block) and Tags, so we
// can exercise assignModuleInfo's description-composition and tag propagation.
type metaStub struct {
	activeStub
	desc string
	tags []string
}

func (m *metaStub) Description() string { return m.desc }
func (m *metaStub) Tags() []string      { return m.tags }

var _ modules.Module = (*metaStub)(nil)

type replacingHook struct {
	replacement *output.ResultEvent
}

func (h *replacingHook) RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	return req, nil
}

func (h *replacingHook) RunPostHooks(*output.ResultEvent) (*output.ResultEvent, error) {
	return h.replacement, nil
}

type classifiedPassiveModule struct {
	*trackingPassiveModule
}

func (m *classifiedPassiveModule) VulnClass() string { return "xss" }

func TestAssignModuleInfo_DescriptionAndTags(t *testing.T) {
	const block = "**What it means:** demo. **How it's exploited:** demo. **Fix:** demo."
	e := &Executor{}
	m := &metaStub{
		activeStub: activeStub{id: "demo-module"},
		desc:       block,
		tags:       []string{"injection", "moderate"},
	}

	t.Run("inline lead is preserved and block appended", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Description: "Demo finding on header X"}}
		e.assignModuleInfo(r, m)
		assert.True(t, strings.HasPrefix(r.Info.Description, "Demo finding on header X"),
			"the module's per-finding context line must stay as the lead")
		assert.Contains(t, r.Info.Description, block, "the explanation block must be appended")
		assert.Contains(t, r.Info.Description, "\n\n", "block must be separated from the lead")
	})

	t.Run("empty inline falls back to the block alone", func(t *testing.T) {
		r := &output.ResultEvent{}
		e.assignModuleInfo(r, m)
		assert.Equal(t, block, r.Info.Description)
	})

	t.Run("tags propagate from the module", func(t *testing.T) {
		r := &output.ResultEvent{}
		e.assignModuleInfo(r, m)
		assert.Equal(t, []string{"injection", "moderate"}, r.Info.Tags)
	})

	t.Run("pre-set tags are not overwritten", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Tags: []string{"nuclei-set"}}}
		e.assignModuleInfo(r, m)
		assert.Equal(t, []string{"nuclei-set"}, r.Info.Tags)
	})

	t.Run("block is not appended twice", func(t *testing.T) {
		r := &output.ResultEvent{Info: output.Info{Description: "lead\n\n" + block}}
		e.assignModuleInfo(r, m)
		assert.Equal(t, 1, strings.Count(r.Info.Description, block),
			"already-composed descriptions must not gain a duplicate block")
	})
}

func TestAssignModuleInfo_EmptyBlockLeavesDescriptionUntouched(t *testing.T) {
	e := &Executor{}
	m := &metaStub{activeStub: activeStub{id: "no-desc"}}
	r := &output.ResultEvent{Info: output.Info{Description: "just the lead", Severity: severity.High}}
	e.assignModuleInfo(r, m)
	assert.Equal(t, "just the lead", r.Info.Description)
}

// newRepoExecutor builds an Executor backed by a fresh in-memory SQLite repo,
// wired with the requestUUIDs cache that emitResult consults for record links.
func newRepoExecutor(t *testing.T) (*Executor, *database.DB) {
	t.Helper()

	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// :memory: is per-connection — pin to one so schema and writes are visible.
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)

	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := database.NewDBFromBun(bunDB, "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	e := &Executor{
		cfg:         ExecutorConfig{},
		repo:        database.NewRepository(db),
		projectUUID: database.DefaultProjectUUID,
		scanUUID:    "test-scan",
		caches:      scanCaches{requestUUIDs: newShardedMap(1)},
	}
	return e, db
}

func countRecords(t *testing.T, db *database.DB) int {
	t.Helper()
	n, err := db.NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
	if err != nil {
		t.Fatalf("count http_records: %v", err)
	}
	return n
}

func loadFindings(t *testing.T, db *database.DB) []*database.Finding {
	t.Helper()
	var findings []*database.Finding
	if err := db.NewSelect().Model(&findings).Scan(context.Background()); err != nil {
		t.Fatalf("load findings: %v", err)
	}
	return findings
}

func TestProcessResults_RecordKindsDoNotInflateFindingsOrCaps(t *testing.T) {
	e, db := newRepoExecutor(t)
	e.cfg.MaxFindingsPerModule = 1
	var findings, candidates, observations int
	e.cfg.OnResult = func(*output.ResultEvent) { findings++ }
	e.cfg.OnCandidate = func(*output.ResultEvent) { candidates++ }
	e.cfg.OnObservation = func(*output.ResultEvent) { observations++ }

	mod := &trackingPassiveModule{id: "kind-test"}
	e.processResults(context.Background(), []*output.ResultEvent{
		{URL: "https://example.com/o", RecordKind: output.RecordKindObservation, EvidenceGrade: output.EvidenceGradeObservation},
		{URL: "https://example.com/c", RecordKind: output.RecordKindCandidate, EvidenceGrade: output.EvidenceGradeCandidate},
		{URL: "https://example.com/f1"},
		{URL: "https://example.com/f2"}, // dropped by the finding-only cap
	}, mod, nil)

	assert.Equal(t, 1, findings)
	assert.Equal(t, 1, candidates)
	assert.Equal(t, 1, observations)
	assert.Len(t, loadFindings(t, db), 3, "observation, candidate, and first finding should be retained")

	defaultCount, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{}).Count(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int64(1), defaultCount, "default vulnerability queries must exclude non-findings")
	observationCount, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		RecordKinds: []string{database.RecordKindObservation},
	}).Count(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int64(1), observationCount)
}

func TestProcessResults_CoordinationUsesPostHookEvent(t *testing.T) {
	replacement := &output.ResultEvent{
		ModuleID:         "hooked-module",
		URL:              "https://example.com/after?id=1",
		FuzzingParameter: "after",
	}
	e := &Executor{
		hooks: &replacingHook{replacement: replacement},
		scanCtx: &modkit.ScanContext{
			ParamFindings: &modkit.ParameterFindingRegistry{},
		},
	}
	mod := &classifiedPassiveModule{trackingPassiveModule: &trackingPassiveModule{id: "hooked-module"}}

	e.processResults(context.Background(), []*output.ResultEvent{{
		URL:              "https://example.com/before?id=1",
		FuzzingParameter: "before",
	}}, mod, nil)

	assert.True(t, e.scanCtx.ParamFindings.HasFinding("https://example.com/after", "after", "xss"))
	assert.False(t, e.scanCtx.ParamFindings.HasFinding("https://example.com/before", "before", "xss"), "pre-hook coordinates must not suppress unrelated work")
}

func TestProcessResults_DuplicateFindingDoesNotConsumeCap(t *testing.T) {
	e, db := newRepoExecutor(t)
	e.cfg.MaxFindingsPerModule = 2
	var callbacks int
	e.cfg.OnResult = func(*output.ResultEvent) { callbacks++ }
	mod := &trackingPassiveModule{id: "dedup-cap-test"}

	e.processResults(context.Background(), []*output.ResultEvent{
		{URL: "https://example.com/a", DedupKey: "root-a"},
		{URL: "https://example.com/a?second-evidence=1", DedupKey: "root-a"},
		{URL: "https://example.com/b", DedupKey: "root-b"},
	}, mod, nil)

	assert.Equal(t, 2, callbacks, "only distinct root causes are dispatched")
	assert.Len(t, loadFindings(t, db), 2, "duplicate evidence is merged and does not crowd out the second root cause")
}

func TestAdmitFinding_DuplicatesCannotRacePastRejectedCap(t *testing.T) {
	e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1}}
	first, allowed := e.admitFinding("admitted-root", "cap-test")
	assert.True(t, first)
	assert.True(t, allowed)

	const workers = 64
	start := make(chan struct{})
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, admitted := e.admitFinding("rejected-root", "cap-test")
			results <- admitted
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for admitted := range results {
		assert.False(t, admitted, "a duplicate must inherit or repeat the rejected cap decision")
	}
}

// TestProcessResults_BaselineFindingLinksWithoutDuplicateRecord proves a finding
// that refers to the unchanged baseline request (request backfilled by
// processResults) links to the baseline's pre-registered http_record via its
// memoized hash — without allocating a temp request, re-hashing, or saving a
// duplicate "finding" record.
func TestProcessResults_BaselineFindingLinksWithoutDuplicateRecord(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	_, rr := makeTestItem("example.com", "/test", "<html>body</html>")

	// Simulate the ingestion-time pre-registration: the baseline request hash
	// already maps to its persisted http_record UUID.
	const baselineUUID = "baseline-record-uuid"
	e.caches.requestUUIDs.Store(rr.Request().ID(), baselineUUID)

	mod := &trackingPassiveModule{id: "passive-test"}
	// Empty Request forces processResults to backfill from the baseline item,
	// which is exactly the signal that the finding is the unchanged baseline.
	results := []*output.ResultEvent{{URL: "https://example.com/test"}}

	e.processResults(ctx, results, mod, rr)

	if got := countRecords(t, db); got != 0 {
		t.Errorf("http_records = %d, want 0 (baseline finding must not create a duplicate record)", got)
	}
	findings := loadFindings(t, db)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := findings[0].HTTPRecordUUIDs; len(got) != 1 || got[0] != baselineUUID {
		t.Errorf("finding linked to %v, want [%s] (the pre-registered baseline record)", got, baselineUUID)
	}
}

// TestProcessResults_MutatedFindingDoesNotLinkBaseline proves the optimization's
// safety guard: when a module reports its own (mutated) request, the finding is
// NOT linked to the baseline record — it gets its own evidence record.
func TestProcessResults_MutatedFindingDoesNotLinkBaseline(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	_, rr := makeTestItem("example.com", "/test", "<html>body</html>")

	const baselineUUID = "baseline-record-uuid"
	e.caches.requestUUIDs.Store(rr.Request().ID(), baselineUUID)

	mod := &trackingPassiveModule{id: "active-test"}
	// A module-supplied request distinct from the baseline: no backfill, so the
	// finding must hash and persist its own evidence rather than reuse baseline.
	results := []*output.ResultEvent{{
		URL:      "https://example.com/mutated?x=evil",
		Request:  "GET /mutated?x=evil HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nzzz",
	}}

	e.processResults(ctx, results, mod, rr)

	if got := countRecords(t, db); got != 1 {
		t.Errorf("http_records = %d, want 1 (mutated finding saves its own evidence record)", got)
	}
	findings := loadFindings(t, db)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	linked := findings[0].HTTPRecordUUIDs
	if len(linked) != 1 || linked[0] == "" {
		t.Fatalf("mutated finding linked to %v, want one non-empty record UUID", linked)
	}
	if linked[0] == baselineUUID {
		t.Errorf("mutated finding incorrectly linked to the baseline record %s", baselineUUID)
	}
}

// newStubRecord builds a request-only HttpRequestResponse (no response), as
// discovery does for endpoints synthesized from a parsed API spec.
func newStubRecord(host, path string) *httpmsg.HttpRequestResponse {
	svc := httpmsg.NewServiceSecure(host, 443, true)
	raw := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host))
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, raw), nil)
}

// TestSaveToDatabase_BackfillsStubResponse is the core regression guard for the
// "spec endpoints show empty traffic" bug: a record stored as a request-only
// stub (status 0, no response) that maps to an existing RecordUUID must have the
// executor's freshly fetched baseline persisted back onto it — not discarded.
func TestSaveToDatabase_BackfillsStubResponse(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	// Persist the stub exactly as the discovery source does.
	stub := newStubRecord("api.example.com", "/api/users")
	uuid, err := e.repo.SaveRecord(ctx, stub, "api-spec", database.DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	if rec, _ := e.repo.GetRecordByUUID(ctx, uuid); rec.HasResponse || rec.StatusCode != 0 {
		t.Fatalf("precondition: stub must have no response, got status=%d hasResp=%v", rec.StatusCode, rec.HasResponse)
	}

	// The item carries the untouched stub (no response) + its RecordUUID; req is
	// the post-fetch copy with the real baseline attached (what the executor
	// passes to saveToDatabase after fetchBaseline).
	item := work.NewWithModules(stub, nil)
	item.RecordUUID = uuid
	req := stub.WithResponse(httpmsg.NewHttpResponse(
		[]byte("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"unauthorized\"}")))

	e.saveToDatabase(ctx, item, req, nil)

	rec, err := e.repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if !rec.HasResponse || rec.StatusCode != 401 {
		t.Errorf("stub response not backfilled: status=%d hasResp=%v", rec.StatusCode, rec.HasResponse)
	}
	if !strings.Contains(rec.ResponseContentType, "application/json") {
		t.Errorf("content-type not backfilled: %q", rec.ResponseContentType)
	}
	if len(rec.RawResponse) == 0 {
		t.Error("raw response not backfilled")
	}
	if got := countRecords(t, db); got != 1 {
		t.Errorf("http_records = %d, want 1 (backfill must UPDATE, not insert a duplicate)", got)
	}
}

// TestSaveToDatabase_DoesNotClobberExistingResponse proves the guard: a record
// that already captured a response (item.Request carries one) is never
// overwritten by the backfill, even if req holds a different response. This
// keeps crawled/ingested records — which already have their real response — safe.
func TestSaveToDatabase_DoesNotClobberExistingResponse(t *testing.T) {
	e, _ := newRepoExecutor(t)
	ctx := context.Background()

	// A record saved WITH a 200 response (a normal crawled/ingested record).
	full := newStubRecord("api.example.com", "/api/health").WithResponse(
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok")))
	uuid, err := e.repo.SaveRecord(ctx, full, "deparos", database.DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}

	item := work.NewWithModules(full, nil)
	item.RecordUUID = uuid
	// A different (500) response that must NOT overwrite the stored 200.
	req := full.WithResponse(httpmsg.NewHttpResponse(
		[]byte("HTTP/1.1 500 Internal Server Error\r\n\r\nboom")))

	e.saveToDatabase(ctx, item, req, nil)

	rec, err := e.repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if rec.StatusCode != 200 {
		t.Errorf("existing response was clobbered: status=%d, want 200", rec.StatusCode)
	}
}

// TestSaveToDatabase_PersistsRedirectChain covers --record-redirect-chain end to
// end at the persistence layer: each hop becomes its own row, oldest first, and
// the rows form one parent_uuid spine ending at the final response.
func TestSaveToDatabase_PersistsRedirectChain(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()

	hop := func(path string, status int, location string) *httpmsg.HttpRequestResponse {
		raw := fmt.Sprintf("HTTP/1.1 %d Moved\r\nLocation: %s\r\n\r\n", status, location)
		return newStubRecord("example.test", path).WithResponse(httpmsg.NewHttpResponse([]byte(raw)))
	}
	hops := []*httpmsg.HttpRequestResponse{
		hop("/one", 301, "/two"),
		hop("/two", 302, "/end"),
	}
	final := newStubRecord("example.test", "/end").WithResponse(
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\narrived")))

	e.saveToDatabase(ctx, work.NewWithModules(final, nil), final, hops)

	if got := countRecords(t, db); got != 3 {
		t.Fatalf("http_records = %d, want 3 (two hops + the final response)", got)
	}

	byPath := map[string]*database.HTTPRecord{}
	recs, err := e.repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "example.test", 10)
	if err != nil {
		t.Fatalf("GetRecordsByHostname: %v", err)
	}
	for _, r := range recs {
		byPath[r.Path] = r
	}

	one, two, end := byPath["/one"], byPath["/two"], byPath["/end"]
	if one == nil || two == nil || end == nil {
		t.Fatalf("missing rows: one=%v two=%v end=%v", one != nil, two != nil, end != nil)
	}
	if one.StatusCode != 301 || two.StatusCode != 302 || end.StatusCode != 200 {
		t.Errorf("statuses = %d/%d/%d, want 301/302/200", one.StatusCode, two.StatusCode, end.StatusCode)
	}
	// The spine. The first hop is the root; everything else points at its
	// predecessor, so the chain is walkable in either direction from any row.
	if one.ParentUUID != "" {
		t.Errorf("first hop has parent %q, want none (it is the root of the chain)", one.ParentUUID)
	}
	if two.ParentUUID != one.UUID {
		t.Errorf("/two parent = %q, want /one (%q)", two.ParentUUID, one.UUID)
	}
	if end.ParentUUID != two.UUID {
		t.Errorf("/end parent = %q, want /two (%q)", end.ParentUUID, two.UUID)
	}
}

// TestAdoptRecordParent_BackfillsOnlyWhenEmpty pins the backfill-never-overwrite
// rule. A row can lose the race to its own chain (a passive module persists the
// final response as finding evidence before the item's own save runs), so an
// unparented row must be able to join a chain afterwards — while a row already
// in one must never be moved out of it by a later scan through the same URL.
func TestAdoptRecordParent_BackfillsOnlyWhenEmpty(t *testing.T) {
	e, _ := newRepoExecutor(t)
	ctx := context.Background()

	save := func(path string) string {
		uuid, err := e.repo.SaveRecord(ctx, newStubRecord("example.test", path), "probe", database.DefaultProjectUUID)
		if err != nil {
			t.Fatalf("SaveRecord(%s): %v", path, err)
		}
		return uuid
	}
	orphan := save("/orphan")
	firstParent := save("/first-parent")
	otherParent := save("/other-parent")

	// Empty parent: adopted.
	e.repo.AdoptRecordParent(ctx, orphan, firstParent)
	rec, _ := e.repo.GetRecordByUUID(ctx, orphan)
	if rec.ParentUUID != firstParent {
		t.Fatalf("parent = %q, want %q (an empty parent must be backfilled)", rec.ParentUUID, firstParent)
	}

	// Already parented: left alone.
	e.repo.AdoptRecordParent(ctx, orphan, otherParent)
	rec, _ = e.repo.GetRecordByUUID(ctx, orphan)
	if rec.ParentUUID != firstParent {
		t.Errorf("parent = %q, want it to stay %q — an existing chain must not be rewritten", rec.ParentUUID, firstParent)
	}

	// Self-link would make the chain a cycle; refused outright.
	e.repo.AdoptRecordParent(ctx, otherParent, otherParent)
	rec, _ = e.repo.GetRecordByUUID(ctx, otherParent)
	if rec.ParentUUID != "" {
		t.Errorf("self-parent was written (%q); a row must never be its own parent", rec.ParentUUID)
	}
}
