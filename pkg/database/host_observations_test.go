package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// obs builds a complete observation for one endpoint. A helper rather than a
// literal per call site: HostObservationInput embeds HostFacts, so spelling it
// out inline buries the one or two fields a test actually cares about.
func obs(host string, port int, facts HostFacts) HostObservationInput {
	return HostObservationInput{Hostname: host, Port: port, HostFacts: facts, Complete: true}
}

// TestHostObservationsSurviveCacheEviction is the regression this table exists
// for.
//
// The DNS and TLS caches hold 8192 entries and evict in insertion order, so on a
// sweep larger than that the hosts resolved FIRST lost their answers before the
// export that wanted them: resolved successfully, then silently absent from the
// output of the very run that resolved them. A stored observation does not
// evict.
func TestHostObservationsSurviveCacheEviction(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "early.example.invalid"
	const port = 443

	// The host is resolved and cached FIRST, as the prefetch stage does, and the
	// observation is stored alongside it. Both halves matter: without the cache
	// entry the eviction below would have nothing to evict and the test would
	// pass without exercising anything.
	dnsCache.Add(host, dnsEntry{
		ip: "192.0.2.1", a: []string{"192.0.2.1"}, aaaa: []string{"2001:db8::1"},
		cname: []string{"origin.example.invalid"}, expiry: time.Now().Add(time.Hour),
		cnameChecked: true,
	})
	t.Cleanup(func() { dnsCache.Remove(host) })
	if LookupHostFacts(host, port).Empty() {
		t.Fatal("test setup: the host was not cached, so there is no eviction to reproduce")
	}

	stored := HostFacts{
		A:     []string{"192.0.2.1"},
		AAAA:  []string{"2001:db8::1"},
		CNAME: []string{"origin.example.invalid"},
	}
	if err := repo.SaveHostObservations(ctx, "", "scan-1",
		[]HostObservationInput{obs(host, port, stored)}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}

	// Now resolve past the cache bound, exactly as a >8192-host sweep does. The
	// cache-only reader is the control: what it could answer a moment ago it can
	// no longer answer, which is the whole defect.
	for i := range dnsCacheMaxEntries + 16 {
		ResolveHostnameNow(ctx, fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	if !LookupHostFacts(host, port).Empty() {
		t.Fatal("test setup: the process cache still holds the host, so eviction was not reproduced")
	}

	got := NewStoredHostFacts(ctx, repo, "", "scan-1").Facts(host, port)
	if got.Empty() {
		t.Fatal("stored observation did not survive cache eviction")
	}
	if len(got.A) != 1 || got.A[0] != "192.0.2.1" {
		t.Errorf("a = %v, want [192.0.2.1]", got.A)
	}
	if len(got.AAAA) != 1 || got.AAAA[0] != "2001:db8::1" {
		t.Errorf("aaaa = %v, want [2001:db8::1]", got.AAAA)
	}
	if len(got.CNAME) != 1 || got.CNAME[0] != "origin.example.invalid" {
		t.Errorf("cname = %v, want [origin.example.invalid]", got.CNAME)
	}
}

// TestHostObservationsPreserveHistoryAcrossRuns pins the §9.2 decision: a repeat
// probe RECORDS a new observation, it does not overwrite the old one. What a
// host resolved to during an earlier scan is that scan's evidence, and an upsert
// keyed on the hostname alone would destroy it every time the host was scanned
// again.
func TestHostObservationsPreserveHistoryAcrossRuns(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "moved.example.invalid"
	runs := map[string]string{"scan-old": "192.0.2.10", "scan-new": "198.51.100.10"}

	for scan, addr := range runs {
		if err := repo.SaveHostObservations(ctx, "", scan,
			[]HostObservationInput{obs(host, 443, HostFacts{A: []string{addr}})}); err != nil {
			t.Fatalf("SaveHostObservations(%s): %v", scan, err)
		}
	}

	for scan, want := range runs {
		got := NewStoredHostFacts(ctx, repo, "", scan).Facts(host, 443)
		if len(got.A) != 1 || got.A[0] != want {
			t.Errorf("%s: a = %v, want [%s] — a later run overwrote an earlier run's evidence", scan, got.A, want)
		}
	}
}

// TestHostObservationsIdempotentWithinOneRun is the other half of the same key:
// a second write for one endpoint inside ONE run is a refinement of that run's
// single observation (the TLS handshake landing after the DNS answer), not a
// second event.
func TestHostObservationsIdempotentWithinOneRun(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "refined.example.invalid"
	in := obs(host, 443, HostFacts{A: []string{"192.0.2.20"}})
	if err := repo.SaveHostObservations(ctx, "", "scan-1", []HostObservationInput{in}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	in.TLS = &tlsprobe.Info{ProbeStatus: true, Host: host}
	if err := repo.SaveHostObservations(ctx, "", "scan-1", []HostObservationInput{in}); err != nil {
		t.Fatalf("second save: %v", err)
	}

	n, err := db.NewSelect().Model((*HostObservation)(nil)).Where("hostname = ?", host).Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d rows for one endpoint in one run, want 1", n)
	}

	if got := NewStoredHostFacts(ctx, repo, "", "scan-1").Facts(host, 443); got.TLS == nil {
		t.Error("the refining write did not land: TLS info is absent")
	}
}

// TestHostObservationsAreProjectScoped: one project's observations must not
// answer for another's, the same isolation every other row in the schema keeps.
func TestHostObservationsAreProjectScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "shared.example.invalid"
	if err := repo.SaveHostObservations(ctx, "project-a", "scan-a",
		[]HostObservationInput{obs(host, 443, HostFacts{A: []string{"192.0.2.30"}})}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}

	if got := NewStoredHostFacts(ctx, repo, "project-b", "").Facts(host, 443); !got.Empty() {
		t.Errorf("project-b sees project-a's observation: %+v", got)
	}
}

// TestHostObservationsPortScoped: two services on one host are two endpoints. A
// hostname-only key would let :443's certificate answer for :8443.
func TestHostObservationsPortScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "multi.example.invalid"
	if err := repo.SaveHostObservations(ctx, "", "scan-1", []HostObservationInput{
		obs(host, 443, HostFacts{TLS: &tlsprobe.Info{ProbeStatus: true, Host: host}}),
		obs(host, 8443, HostFacts{A: []string{"192.0.2.40"}}),
	}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}

	facts := NewStoredHostFacts(ctx, repo, "", "scan-1")
	if got := facts.Facts(host, 443); got.TLS == nil {
		t.Error(":443 lost its TLS info")
	}
	if got := facts.Facts(host, 8443); got.TLS != nil {
		t.Error(":8443 was served :443's certificate")
	}
}

// TestHostObservationHostnameCaseInsensitive: the writer normalizes through
// dnsKey, so the reader must too. A key normalized on one side only makes a
// stored answer invisible to the caller that wanted it.
func TestHostObservationHostnameCaseInsensitive(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.SaveHostObservations(ctx, "", "scan-1",
		[]HostObservationInput{obs("MiXeD.Example.Invalid", 443, HostFacts{A: []string{"192.0.2.50"}})}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}
	if got := NewStoredHostFacts(ctx, repo, "", "scan-1").Facts("mixed.example.invalid", 443); got.Empty() {
		t.Error("a hostname stored with mixed case could not be read back lowercased")
	}
}

// TestHostObservationsEmptyNotStored: an observation with no answer and no
// completeness claim states nothing the absence of a row does not already state.
func TestHostObservationsEmptyNotStored(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.SaveHostObservations(ctx, "", "scan-1", []HostObservationInput{
		{Hostname: "nothing.example.invalid", Port: 443},
		obs("", 443, HostFacts{A: []string{"192.0.2.60"}}),
	}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}
	n, err := db.NewSelect().Model((*HostObservation)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("stored %d rows for empty/hostless observations, want 0", n)
	}
}

// TestHostObservationIncompleteIsDistinguishable: a cut-short prefetch records
// what it got and marks it incomplete. Without the flag "this host has no AAAA
// record" and "we never got to this host" are the same empty answer.
func TestHostObservationIncompleteIsDistinguishable(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.SaveHostObservations(ctx, "", "scan-1", []HostObservationInput{
		obs("done.example.invalid", 443, HostFacts{A: []string{"192.0.2.70"}}),
		{
			Hostname:  "cutshort.example.invalid",
			Port:      443,
			HostFacts: HostFacts{A: []string{"192.0.2.71"}},
			Complete:  false,
		},
	}); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}

	var rows []HostObservation
	if err := db.NewSelect().Model(&rows).Order("hostname ASC").Scan(ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Hostname != "cutshort.example.invalid" || rows[0].Complete {
		t.Errorf("row 0 = %q complete=%v, want cutshort complete=false", rows[0].Hostname, rows[0].Complete)
	}
	if rows[1].Hostname != "done.example.invalid" || !rows[1].Complete {
		t.Errorf("row 1 = %q complete=%v, want done complete=true", rows[1].Hostname, rows[1].Complete)
	}
}

// TestStoredHostFactsFallsBackToCache: an endpoint observed after the
// observations were written - or by a run that stored none - still gets its
// facts from the process caches, so this is strictly additive to the previous
// behaviour.
func TestStoredHostFactsFallsBackToCache(t *testing.T) {
	const host = "cached-only.example.invalid"
	dnsCache.Add(host, dnsEntry{
		ip: "192.0.2.80", a: []string{"192.0.2.80"},
		expiry: time.Now().Add(time.Hour), cnameChecked: true,
	})
	t.Cleanup(func() { dnsCache.Remove(host) })

	facts := NewStoredHostFacts(context.Background(), nil, "", "")
	got := facts.Facts(host, 443)
	if len(got.A) != 1 || got.A[0] != "192.0.2.80" {
		t.Errorf("a = %v, want the cached [192.0.2.80]", got.A)
	}
	if facts.MissingCount() != 0 {
		t.Errorf("MissingCount = %d, want 0 for an endpoint the cache answered", facts.MissingCount())
	}
	// An endpoint neither source knows is what MissingCount is for.
	facts.Facts("unknown.example.invalid", 443)
	if facts.MissingCount() != 1 {
		t.Errorf("MissingCount = %d, want 1", facts.MissingCount())
	}
}

// TestStoredHostFactsDoesNotLoadHistory pins the memory shape of the read path.
//
// Resolution is per-endpoint and memoized, so a project with a long probe
// history costs the same as one with a single run: the reader asks about the
// endpoints it is emitting, not about every observation ever recorded. The
// preload it replaced returned endpoints × runs rows to build a map of
// endpoints, which made exporting a two-record database peak at 842 MB against a
// 120 MB baseline.
func TestStoredHostFactsDoesNotLoadHistory(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// 50 endpoints across 20 runs: 1000 rows of history behind 50 answers.
	for run := range 20 {
		batch := make([]HostObservationInput, 0, 50)
		for h := range 50 {
			batch = append(batch, obs(fmt.Sprintf("h%d.example.invalid", h), 443,
				HostFacts{A: []string{fmt.Sprintf("192.0.2.%d", run)}}))
		}
		if err := repo.SaveHostObservations(ctx, "", fmt.Sprintf("scan-%02d", run), batch); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	if n, err := db.NewSelect().Model((*HostObservation)(nil)).Count(ctx); err != nil || n != 1000 {
		t.Fatalf("setup: %d rows (err %v), want 1000", n, err)
	}

	facts := NewStoredHostFacts(ctx, repo, "", "")
	// Nothing is resolved until asked.
	if facts.Stored() != 0 {
		t.Errorf("Stored() = %d before any lookup, want 0 — the reader preloaded", facts.Stored())
	}

	// The project-wide read takes the most recently RECORDED observation, which
	// is run 19's address, not run 0's.
	got := facts.Facts("h7.example.invalid", 443)
	if len(got.A) != 1 || got.A[0] != "192.0.2.19" {
		t.Errorf("a = %v, want [192.0.2.19] (the latest run's observation)", got.A)
	}
	if facts.Stored() != 1 {
		t.Errorf("Stored() = %d after one lookup, want 1", facts.Stored())
	}

	// Repeated asks are memoized, not re-queried, and do not re-count.
	for range 5 {
		facts.Facts("h7.example.invalid", 443)
	}
	if facts.Stored() != 1 {
		t.Errorf("Stored() = %d after repeating one lookup, want 1", facts.Stored())
	}
}

// TestStoredHostFactsScanScopedPrefersThatRun: when a scan is named, that run's
// own observation answers even though a later run recorded a different one.
// A report about a scan must describe what THAT scan saw.
func TestStoredHostFactsScanScopedPrefersThatRun(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const host = "pinned.example.invalid"
	for _, run := range []struct{ scan, addr string }{
		{"scan-old", "192.0.2.1"}, {"scan-new", "198.51.100.1"},
	} {
		if err := repo.SaveHostObservations(ctx, "", run.scan,
			[]HostObservationInput{obs(host, 443, HostFacts{A: []string{run.addr}})}); err != nil {
			t.Fatalf("%s: %v", run.scan, err)
		}
	}

	got := NewStoredHostFacts(ctx, repo, "", "scan-old").Facts(host, 443)
	if len(got.A) != 1 || got.A[0] != "192.0.2.1" {
		t.Errorf("a = %v, want [192.0.2.1] — the named scan's own observation", got.A)
	}
}
