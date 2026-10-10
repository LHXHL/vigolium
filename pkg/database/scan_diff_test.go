package database

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// diffFixture is three scans of one target and the findings they observed:
//
//	stay   — seen by scan 1 and scan 2
//	gone   — seen by scan 1 only
//	fresh  — seen by scan 2 only (and scan 3)
type diffFixture struct {
	repo              *Repository
	db                *DB
	s1, s2, s3        *Scan
	stay, gone, fresh int64
}

func completedScan(uuid, target string, started time.Time, phases ...string) *Scan {
	s := &Scan{
		UUID: uuid, ProjectUUID: DefaultProjectUUID, Status: "completed", Target: target,
		StartedAt: started, FinishedAt: started.Add(time.Minute), Completeness: CompletenessComplete,
	}
	for _, p := range phases {
		s.PhaseOutcomes = append(s.PhaseOutcomes, PhaseOutcome{Phase: p, State: PhaseCompleted})
	}
	return s
}

// observe saves (or re-detects) a finding under scanUUID.
func observe(t *testing.T, repo *Repository, project, hash, sev, scanUUID string) int64 {
	t.Helper()
	f := &Finding{ProjectUUID: project, ModuleID: "m-" + hash, ModuleName: "M " + hash, Severity: sev,
		Confidence: "firm", FindingHash: hash, ScanUUID: scanUUID}
	if err := repo.SaveFindingDirect(context.Background(), f); err != nil {
		t.Fatalf("save %s: %v", hash, err)
	}
	var id int64
	if err := repo.db.NewRaw("SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?", project, hash).
		Scan(context.Background(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newDiffFixture(t *testing.T) *diffFixture {
	t.Helper()
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	// Start after the store's observation_history_since so history is complete.
	base := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	fx := &diffFixture{repo: repo, db: db,
		s1: completedScan("11111111-0000-0000-0000-000000000001", "https://app.example", base, "discovery", "dynamic-assessment"),
		s2: completedScan("22222222-0000-0000-0000-000000000002", "https://app.example", base.Add(time.Hour), "discovery", "dynamic-assessment"),
		s3: completedScan("33333333-0000-0000-0000-000000000003", "https://app.example, https://api.example", base.Add(2*time.Hour), "discovery", "dynamic-assessment"),
	}
	for _, s := range []*Scan{fx.s1, fx.s2, fx.s3} {
		if err := repo.CreateScan(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	fx.stay = observe(t, repo, DefaultProjectUUID, "stay", SeverityMedium, fx.s1.UUID)
	observe(t, repo, DefaultProjectUUID, "stay", SeverityMedium, fx.s2.UUID)
	fx.gone = observe(t, repo, DefaultProjectUUID, "gone", SeverityLow, fx.s1.UUID)
	fx.fresh = observe(t, repo, DefaultProjectUUID, "fresh", SeverityHigh, fx.s2.UUID)
	observe(t, repo, DefaultProjectUUID, "fresh", SeverityHigh, fx.s3.UUID)
	return fx
}

func diffChanges(d *ScanDiff) map[int64]string {
	out := map[int64]string{}
	for _, e := range d.Entries {
		out[e.Finding.ID] = e.Change
	}
	return out
}

func TestDiffScans_Classes(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)

	d, err := fx.repo.DiffScans(ctx, ScanDiffOptions{ProjectUUID: DefaultProjectUUID, Base: fx.s1, Head: fx.s2})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Comparable || len(d.ComparabilityReasons) != 0 {
		t.Fatalf("comparable = %v %v", d.Comparable, d.ComparabilityReasons)
	}
	if d.History != DiffHistoryComplete {
		t.Errorf("history = %q, want complete", d.History)
	}
	want := map[int64]string{fx.stay: DiffUnchanged, fx.gone: DiffFixed, fx.fresh: DiffNew}
	if got := diffChanges(d); len(got) != 3 || got[fx.stay] != want[fx.stay] || got[fx.gone] != want[fx.gone] || got[fx.fresh] != want[fx.fresh] {
		t.Fatalf("changes = %v, want %v", got, want)
	}
	if d.Counts[DiffNew] != 1 || d.Counts[DiffFixed] != 1 || d.Counts[DiffUnchanged] != 1 || d.Counts[DiffNotReobserved] != 0 {
		t.Errorf("counts = %v", d.Counts)
	}
	// Ordered by class: new, fixed, …, unchanged.
	if d.Entries[0].Change != DiffNew || d.Entries[len(d.Entries)-1].Change != DiffUnchanged {
		t.Errorf("order = %v", d.Entries)
	}
	for _, e := range d.Entries {
		if e.Finding.ID == fx.fresh && e.FirstSeenScan != fx.s2.UUID {
			t.Errorf("fresh first_seen_scan = %q, want scan 2", e.FirstSeenScan)
		}
		if e.Finding.ID == fx.stay && e.FirstSeenScan != fx.s1.UUID {
			t.Errorf("stay first_seen_scan = %q, want scan 1", e.FirstSeenScan)
		}
	}
	// Re-detection moved findings.scan_uuid to scan 3 for "fresh", yet scan 2's
	// diff still sees it: the diff reads observations, not the latest observer.
	var latest string
	_ = fx.db.NewRaw("SELECT scan_uuid FROM findings WHERE id = ?", fx.fresh).Scan(ctx, &latest)
	if latest != fx.s3.UUID {
		t.Fatalf("precondition: fresh.scan_uuid = %q", latest)
	}
}

func TestDiffScans_NotComparableHead(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)

	curtailed := *fx.s2
	curtailed.Completeness = CompletenessPartial
	d, err := fx.repo.DiffScans(ctx, ScanDiffOptions{ProjectUUID: DefaultProjectUUID, Base: fx.s1, Head: &curtailed})
	if err != nil {
		t.Fatal(err)
	}
	if d.Comparable || !slices.Contains(d.ComparabilityReasons, ComparabilityHeadPartial) {
		t.Fatalf("curtailed head comparable=%v reasons=%v", d.Comparable, d.ComparabilityReasons)
	}
	if got := diffChanges(d)[fx.gone]; got != DiffNotReobserved {
		t.Errorf("gone under a curtailed head = %q, want not_reobserved", got)
	}

	// Narrower head: base covered a target the head did not.
	narrow := *fx.s2
	wide := *fx.s1
	wide.Target = "https://app.example, https://admin.example"
	if ok, reasons := ScanComparability(&wide, &narrow); ok || !slices.Contains(reasons, ComparabilityTargetsNotCovered) {
		t.Errorf("narrow head = %v %v", ok, reasons)
	}
	// A phase that ran in base but not to completion in head.
	short := *fx.s2
	short.PhaseOutcomes = []PhaseOutcome{{Phase: "discovery", State: PhaseCompleted}, {Phase: "dynamic-assessment", State: PhasePartial}}
	if ok, reasons := ScanComparability(fx.s1, &short); ok || !slices.Contains(reasons, ComparabilityPhasesNotCovered) {
		t.Errorf("phase-short head = %v %v", ok, reasons)
	}
	// A head that covers MORE than the base is still comparable.
	if ok, reasons := ScanComparability(fx.s2, fx.s3); !ok {
		t.Errorf("superset head not comparable: %v", reasons)
	}
	// Unknown completeness is never comparable.
	unknown := *fx.s2
	unknown.Completeness = ""
	if ok, _ := ScanComparability(fx.s1, &unknown); ok {
		t.Error("unknown completeness read as comparable")
	}
}

func TestDiffScans_DismissedAndProjectIsolation(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)

	// Same hash observed by scan 2 under ANOTHER project never counts here.
	const projB = "99999999-0000-0000-0000-000000000000"
	otherID := observe(t, fx.repo, projB, "gone", SeverityLow, fx.s2.UUID)

	if err := fx.repo.SetFindingStatus(ctx, DefaultProjectUUID, fx.fresh, StatusFalsePositive, "noise", "t"); err != nil {
		t.Fatal(err)
	}
	d, err := fx.repo.DiffScans(ctx, ScanDiffOptions{ProjectUUID: DefaultProjectUUID, Base: fx.s1, Head: fx.s2})
	if err != nil {
		t.Fatal(err)
	}
	got := diffChanges(d)
	if _, ok := got[fx.fresh]; ok {
		t.Error("dismissed finding listed without IncludeDismissed")
	}
	if _, ok := got[otherID]; ok {
		t.Error("another project's finding listed")
	}
	if got[fx.gone] != DiffFixed {
		t.Errorf("gone = %q: another project's observation of the same hash leaked in", got[fx.gone])
	}

	d, err = fx.repo.DiffScans(ctx, ScanDiffOptions{ProjectUUID: DefaultProjectUUID, Base: fx.s1, Head: fx.s2, IncludeDismissed: true})
	if err != nil {
		t.Fatal(err)
	}
	if diffChanges(d)[fx.fresh] != DiffNew {
		t.Error("IncludeDismissed did not keep the dismissed finding")
	}
}

func TestDiffScans_PartialHistory(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)
	old := *fx.s1
	old.StartedAt = time.Now().Add(-48 * time.Hour) // before observation_history_since
	d, err := fx.repo.DiffScans(ctx, ScanDiffOptions{ProjectUUID: DefaultProjectUUID, Base: &old, Head: fx.s2})
	if err != nil {
		t.Fatal(err)
	}
	if d.History != DiffHistoryPartial {
		t.Errorf("history = %q, want partial", d.History)
	}
}

func TestResolveScanRef(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)
	running := &Scan{UUID: "44444444-0000-0000-0000-000000000004", ProjectUUID: DefaultProjectUUID, Status: "running",
		Target: "https://app.example", StartedAt: fx.s3.StartedAt.Add(time.Hour)}
	if err := fx.repo.CreateScan(ctx, running); err != nil {
		t.Fatal(err)
	}

	for ref, want := range map[string]string{
		"latest":                               fx.s3.UUID, // the running scan is skipped
		"previous":                             fx.s2.UUID,
		"LATEST":                               fx.s3.UUID,
		fx.s1.UUID:                             fx.s1.UUID,
		"22222222":                             fx.s2.UUID,
		"44444444-0000-0000-0000-000000000004": running.UUID, // explicit uuid may be running
	} {
		s, err := fx.repo.ResolveScanRef(ctx, DefaultProjectUUID, ref)
		if err != nil || s.UUID != want {
			t.Errorf("ResolveScanRef(%q) = %v, %v; want %s", ref, s, err, want)
		}
	}
	if _, err := fx.repo.ResolveScanRef(ctx, DefaultProjectUUID, "5555"); !errors.Is(err, ErrScanNotFound) {
		t.Errorf("short unknown ref = %v", err)
	}
	if _, err := fx.repo.ResolveScanRef(ctx, "other-project", fx.s1.UUID); !errors.Is(err, ErrScanNotFound) {
		t.Errorf("scan from another project = %v, want ErrScanNotFound", err)
	}

	// Ambiguous prefix names candidates.
	twin := &Scan{UUID: "11111111-9999-0000-0000-000000000009", ProjectUUID: DefaultProjectUUID, Status: "completed", StartedAt: time.Now()}
	if err := fx.repo.CreateScan(ctx, twin); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.repo.ResolveScanRef(ctx, DefaultProjectUUID, "11111111"); err == nil || !strings.Contains(err.Error(), twin.UUID) {
		t.Errorf("ambiguous prefix = %v", err)
	}

	got, err := fx.repo.ScansForTarget(ctx, DefaultProjectUUID, "APP.example/", 2)
	if err != nil || len(got) != 2 || got[0].UUID != fx.s3.UUID || got[1].UUID != fx.s2.UUID {
		t.Fatalf("ScansForTarget = %v, %v", got, err)
	}
	if got, _ := fx.repo.ScansForTarget(ctx, DefaultProjectUUID, "https://api.example", 5); len(got) != 1 {
		t.Errorf("api target scans = %d, want 1 (multi-target row)", len(got))
	}
}

// TestNewSince: findings first observed after the baseline and not by it; the
// fallback for observation-less findings; composition with other filters.
func TestNewSince(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)

	ns, err := fx.repo.ResolveNewSince(ctx, fx.s1)
	if err != nil {
		t.Fatal(err)
	}
	if ns.PartialHistory {
		t.Error("fixture baseline should have complete history")
	}
	ids := func(filters QueryFilters) []int64 {
		t.Helper()
		fs, err := NewFindingsQueryBuilder(fx.db, filters).Execute(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, f := range fs {
			out = append(out, f.ID)
		}
		slices.Sort(out)
		return out
	}
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, NewSince: ns}); !slices.Equal(got, []int64{fx.fresh}) {
		t.Errorf("new since s1 = %v, want [fresh %d]", got, fx.fresh)
	}
	// Since scan 2: fresh was first seen BY scan 2, so nothing is new.
	ns2, _ := fx.repo.ResolveNewSince(ctx, fx.s2)
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, NewSince: ns2}); len(got) != 0 {
		t.Errorf("new since s2 = %v, want none", got)
	}
	// Composes with other filters and with the dismissed exclusion.
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, NewSince: ns, Severity: []string{SeverityLow}}); len(got) != 0 {
		t.Errorf("new since s1 & low = %v", got)
	}
	if err := fx.repo.SetFindingStatus(ctx, DefaultProjectUUID, fx.fresh, StatusAcceptedRisk, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, NewSince: ns, ExcludeStatuses: DismissedFindingStatuses}); len(got) != 0 {
		t.Errorf("dismissed finding still new: %v", got)
	}

	// A scan-less finding stored after the baseline finished counts as new.
	imp := &Finding{ProjectUUID: DefaultProjectUUID, ModuleID: "imp", ModuleName: "Imp", Severity: SeverityHigh,
		Confidence: "firm", FindingHash: "imported", CreatedAt: fx.s1.FinishedAt.Add(time.Minute)}
	if err := fx.repo.SaveFindingDirect(ctx, imp); err != nil {
		t.Fatal(err)
	}
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, NewSince: ns}); !slices.Contains(got, imp.ID) {
		t.Errorf("observation-less finding after baseline missing: %v", got)
	}

	// Duration form.
	after := time.Now().Add(-time.Hour)
	if got := ids(QueryFilters{ProjectUUID: DefaultProjectUUID, CreatedAfter: &after}); len(got) == 0 {
		t.Error("CreatedAfter matched nothing")
	}
}

// TestFailOnGateFilter_ExcludesDismissed: the gate's count leaves dismissed
// findings out.
func TestFailOnGateFilter_ExcludesDismissed(t *testing.T) {
	ctx := context.Background()
	fx := newDiffFixture(t)
	count := func() int64 {
		n, err := NewFindingsQueryBuilder(fx.db, QueryFilters{ProjectUUID: DefaultProjectUUID,
			Severity: []string{SeverityHigh}, ExcludeStatuses: DismissedFindingStatuses}).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 1 {
		t.Fatalf("high findings = %d, want 1", count())
	}
	if err := fx.repo.SetFindingStatus(ctx, DefaultProjectUUID, fx.fresh, StatusFalsePositive, "", ""); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Error("false_positive finding still counted")
	}
}
