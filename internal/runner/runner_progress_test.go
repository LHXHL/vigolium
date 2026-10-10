package runner

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// The dynamic-assessment and full-scan-on-receive sources must be Countable, or
// executorProgress has no total to report for the phase that needs one most.
var (
	_ source.Countable = (*database.DBInputSource)(nil)
	_ source.Countable = (*database.RiskPrioritizedDBInputSource)(nil)
)

// progressOf returns done/total/unit from a decoded event, with ok=false for a
// field that is absent.
func progressOf(ev map[string]any) (done, total float64, hasTotal bool, unit string) {
	done, _ = ev["done"].(float64)
	total, hasTotal = ev["total"].(float64)
	unit, _ = ev["unit"].(string)
	return
}

// TestPhaseFinishedCarriesDoneTotalUnit: a phase with a progress source reports
// done/total/unit on phase.finished (the heartbeat shares fillProgress).
func TestPhaseFinishedCarriesDoneTotalUnit(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "dynamic-assessment", nil)
	tr.setProgress(progressUnitRecords, func() (int64, int64) { return 7, 40 })
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	done, total, hasTotal, unit := progressOf(finished[0])
	if done != 7 || !hasTotal || total != 40 || unit != "records" {
		t.Errorf("done/total/unit = %v/%v(%v)/%q, want 7/40/records", done, total, hasTotal, unit)
	}
}

// TestPhaseWithoutProgressOmitsFields: phases with no count to report leave the
// fields off rather than claiming 0 of 0.
func TestPhaseWithoutProgressOmitsFields(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.finish(context.Background(), nil)

	ev := eventsOfType(t, buf, scanevents.TypePhaseFinished)[0]
	for _, k := range []string{"done", "total", "unit"} {
		if _, ok := ev[k]; ok {
			t.Errorf("phase.finished carries %q with no progress source: %v", k, ev)
		}
	}
}

// TestProgressTotalIsMonotonicUpperBound pins the documented contract: total
// never shrinks between readings and never reads below done, and an unknown
// total (0, nothing seen yet) is omitted rather than reported as zero.
func TestProgressTotalIsMonotonicUpperBound(t *testing.T) {
	type reading struct{ done, total int64 }
	steps := []struct {
		in        reading
		wantDone  int64
		wantTotal int64
		hasTotal  bool
	}{
		{reading{0, 0}, 0, 0, false},    // nothing known yet
		{reading{3, 10}, 3, 10, true},   // first bound
		{reading{5, 8}, 5, 10, true},    // a smaller raw total does not shrink it
		{reading{12, 11}, 12, 12, true}, // done passing a stale bound lifts the bound
		{reading{12, 30}, 12, 30, true}, // a new round grows it
		{reading{13, 0}, 13, 30, true},  // a source that forgot its size keeps the bound
	}

	var cur atomic.Pointer[reading]
	tr := &phaseTracker{phase: "dynamic-assessment"}
	tr.setProgress(progressUnitRecords, func() (int64, int64) {
		r := cur.Load()
		return r.done, r.total
	})
	for i, s := range steps {
		in := s.in
		cur.Store(&in)
		var ev scanevents.Event
		tr.fillProgress(&ev)
		if ev.Done == nil || *ev.Done != s.wantDone {
			t.Errorf("step %d: done = %v, want %d", i, ev.Done, s.wantDone)
		}
		if (ev.Total != nil) != s.hasTotal {
			t.Fatalf("step %d: total present = %v, want %v", i, ev.Total != nil, s.hasTotal)
		}
		if s.hasTotal && *ev.Total != s.wantTotal {
			t.Errorf("step %d: total = %d, want %d", i, *ev.Total, s.wantTotal)
		}
		if ev.Unit != "records" {
			t.Errorf("step %d: unit = %q", i, ev.Unit)
		}
	}
}

// TestTrackTargetsCountsDone: the targets counter a phase advances is what the
// tracker reports, and both halves are nil-safe for a phase with no tracker.
func TestTrackTargetsCountsDone(t *testing.T) {
	tr := &phaseTracker{phase: "heuristics-check"}
	p := tr.trackTargets(4)
	p.Add(1)
	p.Add(2)
	var ev scanevents.Event
	tr.fillProgress(&ev)
	if *ev.Done != 3 || *ev.Total != 4 || ev.Unit != "targets" {
		t.Errorf("done/total/unit = %d/%d/%q, want 3/4/targets", *ev.Done, *ev.Total, ev.Unit)
	}
	p.Set(4)
	tr.fillProgress(&ev)
	if *ev.Done != 4 {
		t.Errorf("after Set(4) done = %d", *ev.Done)
	}

	var none *phaseTracker
	np := none.trackTargets(3)
	np.Add(1) // must not panic
	np.Set(2)
}

// TestObserveExecutorDedupsAndSums: the executor observer registers each executor
// once however many times it runs, and executorProgress sums over them.
func TestObserveExecutorDedupsAndSums(t *testing.T) {
	tr := &phaseTracker{phase: "dynamic-assessment"}
	a, b := &core.Executor{}, &core.Executor{}
	tr.observeExecutor(a)
	tr.observeExecutor(a)
	tr.observeExecutor(b)
	tr.observeExecutor(nil)
	if len(tr.executors) != 2 {
		t.Fatalf("registered %d executors, want 2", len(tr.executors))
	}
	if done, total := tr.executorProgress(); done != 0 || total != 0 {
		t.Errorf("idle executors report %d/%d, want 0/0", done, total)
	}
}

// newBannerRepo opens a file-backed SQLite repository in a temp dir.
func newBannerRepo(t *testing.T) *database.Repository {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "banner.sqlite")
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return database.NewRepository(db)
}

// TestFinishedBannerCountsBeforeFinalize is the 2.4c regression: the banner runs
// BEFORE the completion defer finalizes the scan row (LIFO), and used to read the
// row's total_findings — still 0 — so it printed "findings: 0" a line above the
// summary's "N issues found". It now reads the findings table through the same
// helper the CLI summary uses, so it reports the real count while the row still
// says 0, and on a context that is already cancelled the caller hands it a
// detached one.
func TestFinishedBannerCountsBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	repo := newBannerRepo(t)
	const scanUUID = "11111111-1111-1111-1111-111111111111"
	const otherScan = "22222222-2222-2222-2222-222222222222"
	project := database.DefaultProjectUUID

	for _, u := range []string{scanUUID, otherScan} {
		if err := repo.CreateScan(ctx, &database.Scan{
			UUID: u, ProjectUUID: project, Status: "running", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create scan: %v", err)
		}
	}
	sev := []string{"high", "medium", "medium"}
	for i, s := range sev {
		if err := repo.SaveFindingDirect(ctx, &database.Finding{
			ProjectUUID: project, ScanUUID: scanUUID, ModuleID: "m", ModuleName: "M",
			Severity: s, Confidence: "firm", FindingHash: fmt.Sprintf("h-%d", i),
			URL: "http://a.test/", Hostname: "a.test",
		}); err != nil {
			t.Fatalf("save finding: %v", err)
		}
	}
	// Another scan's finding on the same host must not be counted.
	if err := repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, ScanUUID: otherScan, ModuleID: "m", ModuleName: "M",
		Severity: "low", Confidence: "firm", FindingHash: "h-other",
		URL: "http://a.test/", Hostname: "a.test",
	}); err != nil {
		t.Fatalf("save finding: %v", err)
	}

	if row, err := repo.GetScanByUUID(ctx, scanUUID); err != nil || row.TotalFindings != 0 {
		t.Fatalf("precondition: row total_findings = %v (err %v), want the pre-finalize 0", row, err)
	}

	r := &Runner{repository: repo}
	var out bytes.Buffer
	r.printFinishedBanner(ctx, &out, scanUUID, 3*time.Second)
	if !strings.Contains(out.String(), "findings: 3") {
		t.Errorf("banner = %q, want it to report findings: 3", out.String())
	}

	// After finalization the row and the banner's helper agree.
	if err := repo.CompleteScanWithOutcome(ctx, scanUUID, "", database.ScanCompletion{}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	row, _ := repo.GetScanByUUID(ctx, scanUUID)
	total, tally, err := repo.ScanFindingTotal(ctx, scanUUID)
	if err != nil || int64(total) != int64(row.TotalFindings) || tally["medium"] != 2 || tally["high"] != 1 {
		t.Errorf("ScanFindingTotal = %d %v (err %v), row total = %d", total, tally, err, row.TotalFindings)
	}
}

// TestFinishedBannerWithoutRepository keeps the duration-only line when there
// is no database, and omits the count rather than printing a guessed zero.
func TestFinishedBannerWithoutRepository(t *testing.T) {
	r := &Runner{}
	var out bytes.Buffer
	r.printFinishedBanner(context.Background(), &out, "scan-x", time.Second)
	s := out.String()
	if !strings.Contains(s, "Scan finished") || strings.Contains(s, "findings:") {
		t.Errorf("banner without a repository = %q, want duration only", s)
	}
}
