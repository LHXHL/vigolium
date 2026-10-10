package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestIsFatalPhaseError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("deparos: wordlist missing"), false},
		{"wrapped plain", fmt.Errorf("discovery: %w", errors.New("timeout")), false},
		{"explicit", fatal(errors.New("scan row write failed")), true},
		{"explicit wrapped", fmt.Errorf("x: %w", fatal(errors.New("y"))), true},
		{"leveldb closed", fmt.Errorf("dedup: %w", leveldb.ErrClosed), true},
		{"leveldb closed as text", errors.New("put: leveldb: closed"), true},
		{"record writer closed", fmt.Errorf("save: %w", database.ErrRecordWriterClosed), true},
		{"sql closed", errors.New("bun: sql: database is closed"), true},
		{"sqlite full", errors.New("database or disk is full (13)"), true},
		{"sqlite readonly", errors.New("attempt to write a readonly database (8)"), true},
		{"output closed", fmt.Errorf("write: %w", os.ErrClosed), true},
		{"disk full", &os.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC}, true},
		{"auth lost", fmt.Errorf("x: %w", &AuthLostError{Session: "admin"}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFatalPhaseError(tc.err); got != tc.want {
				t.Fatalf("isFatalPhaseError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
	// fatal keeps the message and the chain.
	cause := &AuthLostError{Session: "s"}
	err := fatal(fmt.Errorf("discovery phase failed: %w", cause))
	var lost *AuthLostError
	if !errors.As(err, &lost) || !strings.HasPrefix(err.Error(), "discovery phase failed: ") {
		t.Fatalf("fatal wrapper lost the chain or message: %v", err)
	}
	if fatal(nil) != nil || fatal(err) != err { //nolint:errorlint // identity check: an already-fatal error must come back as-is
		t.Fatal("fatal(nil) must be nil and fatal(fatal) unchanged")
	}
}

func TestStoppedByScanContext(t *testing.T) {
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if stoppedByScanContext(live, context.Canceled) {
		t.Error("a live context never curtails")
	}
	if !stoppedByScanContext(done, fmt.Errorf("crawl: %w", context.Canceled)) {
		t.Error("a cancelled context with a cancellation error is a curtailment")
	}
	if !stoppedByScanContext(done, &egress.BudgetError{Kind: egress.BudgetGlobal, Limit: 1}) {
		t.Error("a budget refusal under a cancelled context is a curtailment")
	}
	if stoppedByScanContext(done, errors.New("parse failed")) {
		t.Error("an unrelated error is the phase's own even after cancellation")
	}
}

// TestPhaseRunnersCoverPlan: every phase the plan can enable has a dispatch
// entry, so none silently runs as a no-op "completed" phase.
func TestPhaseRunnersCoverPlan(t *testing.T) {
	for _, step := range BuildNativeScanPlan(types.DefaultOptions()).Steps {
		p, ok := defaultPhaseRunners[step.Phase]
		if !ok {
			t.Errorf("phase %s has no entry in defaultPhaseRunners", step.Phase)
			continue
		}
		if p.tag == "" || p.label == "" || p.run == nil {
			t.Errorf("phase %s entry incomplete: %+v", step.Phase, p)
		}
	}
}

type phaseErrorRun struct {
	err    error
	row    *database.Scan
	events []scanevents.Event
	ran    []NativePhase
}

// runWithStubbedPhases runs a real RunNativeScan (scan row, preflight GET to a
// local server, event stream) with discovery and dynamic assessment replaced by
// stubs: discovery runs discover, dynamic assessment only records that it ran.
func runWithStubbedPhases(t *testing.T, uuid string, discover func(r *Runner, ctx context.Context) error) phaseErrorRun {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	t.Cleanup(srv.Close)

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.Targets = []string{srv.URL}
	opts.OnlyPhase = "discovery,dynamic-assessment"
	opts.ScanUUID = uuid
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}

	dbCfg := settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "phase-errors.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, opts.ScanUUID))
	t.Cleanup(func() { scanevents.Install(prev) })

	r, err := New(opts)
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	r.SetSettings(settings)
	r.SetRepository(repo)

	var out phaseErrorRun
	r.phaseRunners = map[NativePhase]phaseRunner{
		PhaseDiscovery: {tag: "discovery", label: "discovery", run: func(r *Runner, ctx context.Context, _ *phaseInfra) error {
			out.ran = append(out.ran, PhaseDiscovery)
			return discover(r, ctx)
		}},
		PhaseDynamicAssessment: {tag: "dynamic-assessment", label: "dynamic-assessment", run: func(*Runner, context.Context, *phaseInfra) error {
			out.ran = append(out.ran, PhaseDynamicAssessment)
			return nil
		}},
	}
	out.err = r.RunNativeScan()
	r.Close()

	out.row, err = repo.GetScanByUUID(context.Background(), opts.ScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var ev scanevents.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		out.events = append(out.events, ev)
	}
	return out
}

// phaseEventGolden renders the phase-scoped events as one line each, so the
// expected stream reads as a golden list.
func phaseEventGolden(events []scanevents.Event) []string {
	var lines []string
	for _, ev := range events {
		switch ev.Type {
		case scanevents.TypePhaseStarted:
			lines = append(lines, ev.Type+" "+ev.Phase)
		case scanevents.TypePhaseFinished:
			lines = append(lines, fmt.Sprintf("%s %s %s %v", ev.Type, ev.Phase, ev.Status, ev.Reasons))
		case scanevents.TypeError:
			lines = append(lines, fmt.Sprintf("%s %s %s", ev.Type, ev.Phase, ev.Message))
		}
	}
	return lines
}

func outcomeOf(row *database.Scan, phase NativePhase) (database.PhaseOutcome, bool) {
	for _, o := range row.PhaseOutcomes {
		if o.Phase == string(phase) {
			return o, true
		}
	}
	return database.PhaseOutcome{}, false
}

func assertGolden(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("phase events:\n  got  %q\n  want %q", got, want)
	}
}

func TestDiscoveryErrorContinuesScan(t *testing.T) {
	run := runWithStubbedPhases(t, "phase-error-continue", func(*Runner, context.Context) error {
		return errors.New("deparos exploded")
	})
	if run.err != nil {
		t.Fatalf("RunNativeScan = %v, want nil: a failed discovery must not end the scan", run.err)
	}
	if got := fmt.Sprint(run.ran); got != "[discovery dynamic-assessment]" {
		t.Fatalf("phases ran = %s, want discovery then dynamic-assessment", got)
	}
	disc, ok := outcomeOf(run.row, PhaseDiscovery)
	if !ok || disc.State != database.PhaseFailed || fmt.Sprint(disc.Reasons) != "[phase_error]" || disc.Message != "deparos exploded" {
		t.Fatalf("discovery outcome = %+v, want failed/[phase_error] with the message", disc)
	}
	if da, ok := outcomeOf(run.row, PhaseDynamicAssessment); !ok || da.State != database.PhaseCompleted {
		t.Fatalf("dynamic-assessment outcome = %+v, want completed", da)
	}
	if run.row.Status != "completed" || run.row.ErrorMessage != "" {
		t.Fatalf("scan row status=%q error=%q, want completed with no error", run.row.Status, run.row.ErrorMessage)
	}
	if run.row.Completeness != database.CompletenessPartial || run.row.StopReason != database.ReasonPhaseError {
		t.Fatalf("scan row completeness=%q stop_reason=%q, want partial/phase_error", run.row.Completeness, run.row.StopReason)
	}
	assertGolden(t, phaseEventGolden(run.events), []string{
		"phase.started discovery",
		"error discovery deparos exploded",
		"phase.finished discovery failed [phase_error]",
		"phase.started dynamic-assessment",
		"phase.finished dynamic-assessment completed []",
	})
}

func TestFatalPhaseErrorStopsScan(t *testing.T) {
	run := runWithStubbedPhases(t, "phase-error-fatal", func(*Runner, context.Context) error {
		return fmt.Errorf("save record: %w", database.ErrRecordWriterClosed)
	})
	if run.err == nil || !errors.Is(run.err, errFatal) {
		t.Fatalf("RunNativeScan = %v, want a fatal error", run.err)
	}
	const wantMsg = "discovery phase failed: save record: record writer is closed"
	if run.err.Error() != wantMsg {
		t.Fatalf("error = %q, want %q", run.err, wantMsg)
	}
	if got := fmt.Sprint(run.ran); got != "[discovery]" {
		t.Fatalf("phases ran = %s, want only discovery", got)
	}
	// The returned error is what the CLI puts on scan.finished; the row holds it too.
	if run.row.Status != "failed" || run.row.ErrorMessage != wantMsg {
		t.Fatalf("scan row status=%q error=%q", run.row.Status, run.row.ErrorMessage)
	}
	disc, _ := outcomeOf(run.row, PhaseDiscovery)
	if disc.State != database.PhaseFailed || len(disc.Reasons) != 0 {
		t.Fatalf("discovery outcome = %+v, want failed with no phase_error reason", disc)
	}
	if da, ok := outcomeOf(run.row, PhaseDynamicAssessment); !ok || da.State != database.PhaseSkipped || fmt.Sprint(da.Reasons) != "[error]" {
		t.Fatalf("dynamic-assessment outcome = %+v, want skipped/[error]", da)
	}
	// No non-fatal `error` event: the failure rides on scan.finished.
	assertGolden(t, phaseEventGolden(run.events), []string{
		"phase.started discovery",
		"phase.finished discovery failed []",
	})
}

func TestPhaseStoppedByCancellationIsNotAFailure(t *testing.T) {
	run := runWithStubbedPhases(t, "phase-error-cancel", func(r *Runner, ctx context.Context) error {
		r.cancel()
		<-ctx.Done()
		return fmt.Errorf("crawl: %w", ctx.Err())
	})
	if run.err != nil {
		t.Fatalf("RunNativeScan = %v, want nil for an operator cancellation", run.err)
	}
	if got := fmt.Sprint(run.ran); got != "[discovery]" {
		t.Fatalf("phases ran = %s, want only discovery", got)
	}
	disc, _ := outcomeOf(run.row, PhaseDiscovery)
	if disc.State != database.PhasePartial || fmt.Sprint(disc.Reasons) != "[cancelled]" {
		t.Fatalf("discovery outcome = %+v, want partial/[cancelled]", disc)
	}
	if da, _ := outcomeOf(run.row, PhaseDynamicAssessment); da.State != database.PhaseSkipped {
		t.Fatalf("dynamic-assessment outcome = %+v, want skipped", da)
	}
	assertGolden(t, phaseEventGolden(run.events), []string{
		"phase.started discovery",
		"phase.finished discovery curtailed [cancelled]",
	})
}
