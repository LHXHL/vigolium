package surface_scoring

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// fakeUpdater captures what the module would have written to the database.
type fakeUpdater struct {
	mu     sync.Mutex
	scores map[string]int
	calls  int
	err    error
}

func newFakeUpdater() *fakeUpdater {
	return &fakeUpdater{scores: make(map[string]int)}
}

func (f *fakeUpdater) UpdateSurfaceScores(_ context.Context, scores map[string]int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	for k, v := range scores {
		f.scores[k] = v
	}
	return f.err
}

// fakeResolver maps request hashes to record UUIDs. An unknown hash resolves to
// "", mirroring a record that is not (yet) persisted.
type fakeResolver struct {
	byHash map[string]string
}

func (f *fakeResolver) ResolveRequestUUID(hash string) string { return f.byHash[hash] }

// fakeAnnotator captures what the module would have written to
// http_records.technology.
type fakeAnnotator struct {
	mu    sync.Mutex
	tech  map[string][]string
	calls int
}

func newFakeAnnotator() *fakeAnnotator {
	return &fakeAnnotator{tech: make(map[string][]string)}
}

func (f *fakeAnnotator) SetRecordTechnology(_ context.Context, technology map[string][]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	for k, v := range technology {
		f.tech[k] = v
	}
	return nil
}

// scanContextWith builds a ScanContext wired to the fakes plus the real
// registries, so tests exercise the same lookups production does.
func scanContextWith(updater *fakeUpdater, resolver *fakeResolver) *modkit.ScanContext {
	return &modkit.ScanContext{
		SurfaceScoreUpdater: updater,
		RequestUUIDResolver: resolver,
		TechAnnotator:       newFakeAnnotator(),
		TechStack:           modkit.NewTechRegistry(),
		ContentClass:        modkit.NewContentClassRegistry(),
	}
}

// annotatorFrom pulls the fake back out of a ScanContext built by
// scanContextWith, so a test can assert on the technology column.
func annotatorFrom(t *testing.T, scanCtx *modkit.ScanContext) *fakeAnnotator {
	t.Helper()
	a, ok := scanCtx.TechAnnotator.(*fakeAnnotator)
	if !ok {
		t.Fatalf("TechAnnotator is %T, want *fakeAnnotator", scanCtx.TechAnnotator)
	}
	return a
}

// feed runs one record through the module, registering its request hash with the
// resolver first so it resolves to uuid.
func feed(t *testing.T, m *Module, scanCtx *modkit.ScanContext, resolver *fakeResolver,
	uuid, rawURL string, status int, headers map[string]string, body string) {
	t.Helper()
	item := buildItem(t, rawURL, status, headers, body)
	resolver.byHash[item.Request().ID()] = uuid
	if _, err := m.ScanPerRequest(item, scanCtx); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
}

func TestModuleIdentity(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
}

func TestScanPerRequestEmitsNoFindings(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	item := buildItem(t, "https://example.com/", 200, map[string]string{"Content-Type": "text/html"}, "<html><body>x</body></html>")
	resolver.byHash[item.Request().ID()] = "uuid-1"

	results, err := m.ScanPerRequest(item, scanCtx)
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0 — the score is record metadata, not a finding", len(results))
	}
	// Nothing may be written before Flush.
	if updater.calls != 0 {
		t.Errorf("updater called %d times during ScanPerRequest, want 0", updater.calls)
	}
}

// TestFlushResolvesTechStackSignal is the core of the two-phase design: the tech
// stack is marked AFTER the record was scanned, exactly as happens when the
// fingerprint module runs concurrently with this one, and the record must still
// receive the point.
func TestFlushResolvesTechStackSignal(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	feed(t, m, scanCtx, resolver, "uuid-1", "https://example.com/api/items", 200,
		map[string]string{"Content-Type": "application/json"}, `{"items":[]}`)

	// The fingerprint module publishes after the record was already scanned.
	scanCtx.MarkTech("example.com", "django")

	m.Flush(scanCtx)

	// json + responsive + api-surface (the /api/ path) + techstack = 4 of 16.
	if got := updater.scores["uuid-1"]; got != 23 {
		t.Errorf("surface score = %d, want 23 (json + responsive + api + techstack)", got)
	}
}

// TestFlushWritesTechnology covers the second column the flush owns: the host's
// detected stack must land on every record of that host, sorted, so a consumer
// reading http_records never has to cross-reference the findings table to learn
// what the target runs.
func TestFlushWritesTechnology(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	annotator := annotatorFrom(t, scanCtx)
	m := New()

	htmlCT := map[string]string{"Content-Type": "text/html"}
	feed(t, m, scanCtx, resolver, "uuid-1", "https://example.com/", 200, htmlCT, "<html><body>x</body></html>")
	feed(t, m, scanCtx, resolver, "uuid-2", "https://example.com/about", 200, htmlCT, "<html><body>y</body></html>")

	// Two fingerprint modules publish, out of alphabetical order.
	scanCtx.MarkTech("example.com", "nginx")
	scanCtx.MarkTech("example.com", "django")

	m.Flush(scanCtx)

	want := []string{"django", "nginx"}
	for _, uuid := range []string{"uuid-1", "uuid-2"} {
		got := annotator.tech[uuid]
		if len(got) != len(want) {
			t.Fatalf("%s technology = %v, want %v", uuid, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s technology = %v, want %v (sorted, so two identical scans do not diff)", uuid, got, want)
			}
		}
	}
}

// TestFlushTechStackIsPerHost verifies the host-scoped signal reaches only the
// host it was marked on, and that the key includes the port - a stack on :443
// must not credit records served from :8443.
//
// Asserted on the technology column rather than the score, because the score is
// a popcount: :8443 earns SignalNonStandardPort in place of SignalTechStack and
// lands on the same number by a different route, which would let the regression
// this test exists for pass unnoticed.
func TestFlushTechStackIsPerHost(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	annotator := annotatorFrom(t, scanCtx)
	m := New()

	jsonCT := map[string]string{"Content-Type": "application/json"}
	feed(t, m, scanCtx, resolver, "on-443", "https://example.com/api", 200, jsonCT, `{"a":1}`)
	feed(t, m, scanCtx, resolver, "on-8443", "https://example.com:8443/api", 200, jsonCT, `{"a":1}`)
	feed(t, m, scanCtx, resolver, "other-host", "https://other.example/api", 200, jsonCT, `{"a":1}`)

	// MarkTech uses the URL host, which for the default port is the bare hostname.
	scanCtx.MarkTech("example.com", "django")

	m.Flush(scanCtx)

	if got := annotator.tech["on-443"]; len(got) != 1 || got[0] != "django" {
		t.Errorf("example.com technology = %v, want [django]", got)
	}
	if got := annotator.tech["on-8443"]; len(got) != 0 {
		t.Errorf("example.com:8443 technology = %v, want none - a stack on :443 must not credit :8443", got)
	}
	if got := annotator.tech["other-host"]; len(got) != 0 {
		t.Errorf("other.example technology = %v, want none", got)
	}

	// json + responsive + api-surface, plus techstack only on the marked host.
	if got := updater.scores["on-443"]; got != 23 {
		t.Errorf("example.com record = %d, want 23", got)
	}
	if got := updater.scores["other-host"]; got != 17 {
		t.Errorf("other.example record = %d, want 17", got)
	}
}

// TestFlushSkipsTechnologyForUnknownHost verifies a host no fingerprint module
// recognised writes nothing rather than blanking the column with an empty list.
func TestFlushSkipsTechnologyForUnknownHost(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	annotator := annotatorFrom(t, scanCtx)
	m := New()

	feed(t, m, scanCtx, resolver, "uuid-1", "https://example.com/", 200,
		map[string]string{"Content-Type": "text/html"}, "<html><body>x</body></html>")
	m.Flush(scanCtx)

	if annotator.calls != 0 {
		t.Errorf("annotator called %d times with no tech detected, want 0", annotator.calls)
	}
}

// TestManyHostsAreAllScored is the regression guard for the cap rework. The
// buffer used to be bounded at 1000 distinct hosts, which is exactly the shape a
// host sweep produces: `run probe -T hosts.txt` buffers one record per host, so
// a list longer than the cap silently stopped scoring partway through while the
// module used a trivial amount of memory. The bound is now on total entries.
func TestManyHostsAreAllScored(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	const hosts = 1200
	htmlCT := map[string]string{"Content-Type": "text/html"}
	for i := 0; i < hosts; i++ {
		feed(t, m, scanCtx, resolver, fmt.Sprintf("uuid-%d", i),
			fmt.Sprintf("https://host%d.example/", i), 200, htmlCT, "<html><body>x</body></html>")
	}
	m.Flush(scanCtx)

	if len(updater.scores) != hosts {
		t.Errorf("scored %d of %d hosts - a sweep longer than the old 1000-host cap must score every host",
			len(updater.scores), hosts)
	}
}

// TestScanPerRequestSkipsUnresolvableRecord verifies a record that never reaches
// the database is dropped at flush — there is no row to score.
func TestScanPerRequestSkipsUnresolvableRecord(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	// Deliberately never registered with the resolver.
	item := buildItem(t, "https://example.com/", 200, map[string]string{"Content-Type": "text/html"}, "<html><body>x</body></html>")
	if _, err := m.ScanPerRequest(item, scanCtx); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	m.Flush(scanCtx)

	if updater.calls != 0 {
		t.Errorf("updater called %d times, want 0 for an unpersisted record", updater.calls)
	}
}

// TestUUIDIsResolvedAtFlush is a regression guard. Records are persisted
// asynchronously by the record writer, so during ScanPerRequest the row usually
// does not exist yet and ResolveRequestUUID returns "". Resolving at that point
// silently dropped EVERY record on a real scan — the whole corpus scored 0,
// which is indistinguishable from "no surface found". The hash must be buffered
// and resolved at flush, after the writers have drained.
func TestUUIDIsResolvedAtFlush(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	item := buildItem(t, "https://example.com/api", 200,
		map[string]string{"Content-Type": "application/json"}, `{"a":1}`)

	// Scanned while the row is still unwritten: nothing resolves yet.
	if _, err := m.ScanPerRequest(item, scanCtx); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}

	// The record writer lands the row only now.
	resolver.byHash[item.Request().ID()] = "uuid-late"

	m.Flush(scanCtx)

	if got := updater.scores["uuid-late"]; got != 17 {
		t.Errorf("surface score = %d, want 17 - the hash must be resolved at flush, not at scan time", got)
	}
}

// TestNoUpdaterIsNoOp covers a stateless scan with no repository wired.
func TestNoUpdaterIsNoOp(t *testing.T) {
	m := New()
	scanCtx := &modkit.ScanContext{}

	item := buildItem(t, "https://example.com/", 200, map[string]string{"Content-Type": "text/html"}, "<html><body>x</body></html>")
	if _, err := m.ScanPerRequest(item, scanCtx); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	m.Flush(scanCtx) // must not panic
}

// TestFlushIsIdempotent verifies the buffer is taken, not copied: a second Flush
// must not rewrite the same scores.
func TestFlushIsIdempotent(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	feed(t, m, scanCtx, resolver, "uuid-1", "https://example.com/api", 200,
		map[string]string{"Content-Type": "application/json"}, `{"a":1}`)

	m.Flush(scanCtx)
	m.Flush(scanCtx)

	if updater.calls != 1 {
		t.Errorf("updater called %d times across two flushes, want 1", updater.calls)
	}
}

// TestMaxRecordsPerHost verifies the per-host cap bounds the buffer rather than
// growing it without limit.
func TestMaxRecordsPerHost(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	jsonCT := map[string]string{"Content-Type": "application/json"}
	for i := 0; i < maxRecordsPerHost+10; i++ {
		feed(t, m, scanCtx, resolver, fmt.Sprintf("uuid-%d", i),
			fmt.Sprintf("https://example.com/api/%d", i), 200, jsonCT, `{"a":1}`)
	}
	m.Flush(scanCtx)

	if len(updater.scores) != maxRecordsPerHost {
		t.Errorf("scored %d records, want the cap of %d", len(updater.scores), maxRecordsPerHost)
	}
}

// TestConcurrentScanPerRequest exercises the mutex under the executor's
// ParallelPassive fan-out.
func TestConcurrentScanPerRequest(t *testing.T) {
	updater, resolver := newFakeUpdater(), &fakeResolver{byHash: map[string]string{}}
	scanCtx := scanContextWith(updater, resolver)
	m := New()

	jsonCT := map[string]string{"Content-Type": "application/json"}
	const n = 50
	items := make([]*httpmsg.HttpRequestResponse, n)
	for i := range items {
		items[i] = buildItem(t, fmt.Sprintf("https://example.com/api/%d", i), 200, jsonCT, `{"a":1}`)
		resolver.byHash[items[i].Request().ID()] = fmt.Sprintf("uuid-%d", i)
	}

	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		go func(item *httpmsg.HttpRequestResponse) {
			defer wg.Done()
			if _, err := m.ScanPerRequest(item, scanCtx); err != nil {
				t.Errorf("ScanPerRequest: %v", err)
			}
		}(item)
	}
	wg.Wait()
	m.Flush(scanCtx)

	if len(updater.scores) != n {
		t.Errorf("scored %d records, want %d", len(updater.scores), n)
	}
}
