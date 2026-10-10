package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// budgetRunner builds a Runner whose infrastructure is armed with the given
// request budget, against srv. The returned ctx is the one the phases run
// under (cancelled by the scan-wide limit).
func budgetRunner(t *testing.T, maxRequests, perHost int64, srv *httptest.Server) (*Runner, *phaseInfra, context.Context) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.RateLimit = 0
	opts.Targets = []string{srv.URL}
	opts.MaxRequests = maxRequests
	opts.MaxRequestsPerHost = perHost
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r := &Runner{options: opts, settings: paceSettings(nil)}
	ctx, stop := r.armRequestBudget(context.Background())
	t.Cleanup(stop)
	infra, err := r.buildInfrastructure(ctx, NativeScanPlan{})
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	t.Cleanup(infra.Close)
	return r, infra, ctx
}

func sendN(t *testing.T, ctx context.Context, infra *phaseInfra, url string, n int) (ok int, errs []error) {
	t.Helper()
	for range n {
		in, err := httpmsg.GetRawRequestFromURL(url)
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := infra.httpRequester.WithContext(ctx).Execute(in, vighttp.Options{NoClustering: true})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		resp.Close()
		ok++
	}
	return ok, errs
}

// The scan-wide budget is exact on the requester (a request over it is never
// dialed), and running it out cancels the phase context with the budget as its
// cause: the running phase and every phase after it are attributed to
// request_budget and the scan ends partial with that stop reason.
func TestRequestBudget_GlobalExhaustionIsPartial(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r, infra, ctx := budgetRunner(t, 3, 0, srv)

	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), infra.httpRequester)
	r.currentPhase.Store(tracker)
	ok, errs := sendN(t, ctx, infra, srv.URL+"/x", 5)
	if ok != 3 || hits.Load() != 3 {
		t.Fatalf("sent %d, server saw %d; want exactly 3 (the budget)", ok, hits.Load())
	}
	if len(errs) == 0 || !errors.Is(errs[0], egress.ErrBudgetExhausted) {
		t.Fatalf("refused request error = %v, want ErrBudgetExhausted", errs)
	}
	if egress.BudgetCause(ctx) == nil {
		t.Fatal("exhaustion did not cancel the scan context with the budget as its cause")
	}

	r.currentPhase.Store(nil)
	r.scanOutcome.append(tracker.finish(ctx, nil))
	r.recordSkippedSteps([]NativePhaseStep{{Phase: PhaseKnownIssueScan, Enabled: true}}, scanStopReason(ctx, context.Background()))

	c := r.Completion()
	if c.Completeness != database.CompletenessPartial || c.StopReason != database.ReasonRequestBudget {
		t.Fatalf("completion = %s / %q, want partial / request_budget", c.Completeness, c.StopReason)
	}
	for _, p := range c.Phases {
		if !slices.Contains(p.Reasons, database.ReasonRequestBudget) {
			t.Errorf("phase %s reasons = %v, want request_budget", p.Phase, p.Reasons)
		}
		if slices.Contains(p.Reasons, database.ReasonCancelled) {
			t.Errorf("phase %s reads as cancelled: %v", p.Phase, p.Reasons)
		}
	}
}

// A host that runs out of its per-host budget is a LIMIT on the running phase
// (host_request_budget plus the host), not a reason: the scan stays complete,
// and the scan-wide context is not cancelled.
func TestRequestBudget_PerHostIsALimit(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r, infra, ctx := budgetRunner(t, 0, 2, srv)

	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), infra.httpRequester)
	r.currentPhase.Store(tracker)
	ok, errs := sendN(t, ctx, infra, srv.URL+"/y", 4)
	if ok != 2 || hits.Load() != 2 || len(errs) != 2 {
		t.Fatalf("ok=%d hits=%d refused=%d, want 2/2/2", ok, hits.Load(), len(errs))
	}
	var be *egress.BudgetError
	if !errors.As(errs[0], &be) || be.Kind != egress.BudgetHost {
		t.Fatalf("refusal = %v, want a host BudgetError", errs[0])
	}
	if ctx.Err() != nil {
		t.Fatal("a per-host limit cancelled the scan")
	}
	r.currentPhase.Store(nil)
	out := tracker.finish(ctx, nil)
	if out.State != database.PhaseCompleted ||
		!slices.Contains(out.Limits, database.LimitHostRequestBudget) ||
		!slices.Equal(out.BudgetExhaustedHosts, []string{"127.0.0.1"}) {
		t.Fatalf("outcome = state %s limits %v hosts %v", out.State, out.Limits, out.BudgetExhaustedHosts)
	}
}

// No budget: armRequestBudget leaves the context alone and the gate unbudgeted.
func TestRequestBudget_OffByDefault(t *testing.T) {
	r := &Runner{options: types.DefaultOptions()}
	ctx := context.Background()
	got, stop := r.armRequestBudget(ctx)
	defer stop()
	if got != ctx || r.requestBudget != nil {
		t.Fatal("no flags set must arm no budget")
	}
}

// The direct scan-url / scan-request path folds the budget into its verdict.
func TestApplyRequestBudget(t *testing.T) {
	base := DirectScanCompletion(core.ExecutionReport{Responded: 1}, true, false, nil, database.TargetTally{})
	if base.Completeness != database.CompletenessComplete {
		t.Fatalf("baseline completion = %s", base.Completeness)
	}
	if got := ApplyRequestBudget(base, nil); got.Completeness != database.CompletenessComplete {
		t.Fatal("a nil budget changed the verdict")
	}

	b := egress.NewBudget(3, 1)
	g := egress.New(egress.Config{}).WithBudget(b)
	for i, hp := range []string{"a.test:80", "a.test:80", "b.test:80", "c.test:80", "d.test:80"} {
		release, err := g.Acquire(context.Background(), hp, egress.LaneNormal)
		wantRefused := i == 1 || i == 4 // a.test's second (per-host), d.test (scan-wide)
		if (err != nil) != wantRefused {
			t.Fatalf("attempt %d to %s: err = %v, want refused=%v", i, hp, err, wantRefused)
		}
		if err == nil {
			release(egress.Outcome{})
		}
	}
	got := ApplyRequestBudget(base, b)
	if got.Completeness != database.CompletenessPartial || got.StopReason != database.ReasonRequestBudget {
		t.Fatalf("got %s / %q, want partial / request_budget", got.Completeness, got.StopReason)
	}
	da := got.Phases[len(got.Phases)-1]
	if da.Phase != string(PhaseDynamicAssessment) || !slices.Contains(da.Reasons, database.ReasonRequestBudget) ||
		!slices.Contains(da.Limits, database.LimitHostRequestBudget) || !slices.Equal(da.BudgetExhaustedHosts, []string{"a.test"}) {
		t.Fatalf("assessment outcome = %+v", da)
	}
}

// The spidering floor: only a factor-derived per-target budget is raised, to
// 60s, capped at half the total scan budget; explicit values are untouched.
func TestSpideringFloor(t *testing.T) {
	cases := []struct {
		name    string
		derived time.Duration
		source  string
		scanMax time.Duration
		want    time.Duration
	}{
		{"factor-derived 24s (4m scan) is raised to 60s", 24 * time.Second, string(config.PaceSourceFactor), 4 * time.Minute, 60 * time.Second},
		{"explicit 24s stays 24s", 24 * time.Second, SpideringSourceFlag, 4 * time.Minute, 24 * time.Second},
		{"explicit phase max_duration stays", 24 * time.Second, string(config.PaceSourcePhase), 4 * time.Minute, 24 * time.Second},
		{"90s total caps the floor at 45s", 9 * time.Second, string(config.PaceSourceFactor), 90 * time.Second, 45 * time.Second},
		{"no total budget: plain 60s floor", 12 * time.Second, string(config.PaceSourceFactor), 0, 60 * time.Second},
		{"derived above the floor is unchanged", 6 * time.Minute, string(config.PaceSourceFactor), time.Hour, 6 * time.Minute},
		{"cap never shrinks a derived value", 50 * time.Second, string(config.PaceSourceFactor), 60 * time.Second, 50 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &types.Options{SpideringMaxDuration: tc.derived, SpideringMaxDurationSource: tc.source, ScanMaxDuration: tc.scanMax}
			if got := SpideringBudget(nil, opts); got != tc.want {
				t.Fatalf("SpideringBudget = %s, want %s", got, tc.want)
			}
		})
	}
}

// ApplyScanPace records where the spidering budget came from, so the floor sees
// a --scanning-max-duration-derived value as derived and a typed one as typed;
// and the banner reads the same SpideringBudget the phase does.
func TestApplyScanPace_SpideringSourceAndBanner(t *testing.T) {
	settings := paceSettings(func(p *config.ScanningPaceConfig) { p.MaxDuration = "4m" })

	derived := types.DefaultOptions()
	derived.ScanMaxDuration = 4 * time.Minute
	if err := ApplyScanPace(settings, derived, ExplicitPace{}); err != nil {
		t.Fatal(err)
	}
	if derived.SpideringMaxDuration != 24*time.Second || derived.SpideringMaxDurationSource != string(config.PaceSourceFactor) {
		t.Fatalf("derived = %s from %q, want 24s from factor", derived.SpideringMaxDuration, derived.SpideringMaxDurationSource)
	}
	if got := SpideringBudget(settings, derived); got != 60*time.Second {
		t.Fatalf("phase budget = %s, want the 60s floor", got)
	}
	// banner == phase: the banner label is rendered from the same budget.
	if label := PhaseLabel(settings, "Spidering", "spidering", true, SpideringBudget(settings, derived)); !strings.Contains(terminal.StripANSI(label), "1m0s") {
		t.Fatalf("banner label %q does not show the floored 1m0s budget", label)
	}

	typed := types.DefaultOptions()
	typed.ScanMaxDuration = 4 * time.Minute
	typed.SpideringMaxDuration = 24 * time.Second
	if err := ApplyScanPace(settings, typed, ExplicitPace{SpideringMaxDuration: true}); err != nil {
		t.Fatal(err)
	}
	if got := SpideringBudget(settings, typed); got != 24*time.Second {
		t.Fatalf("typed --spider-max-time 24s became %s", got)
	}
}

// scanning_pace.max_requests fills an untyped flag; a typed one wins.
func TestApplyScanPace_RequestBudget(t *testing.T) {
	settings := paceSettings(func(p *config.ScanningPaceConfig) {
		p.MaxRequests = 500
		p.MaxRequestsPerHost = 50
	})
	opts := types.DefaultOptions()
	if err := ApplyScanPace(settings, opts, ExplicitPace{}); err != nil {
		t.Fatal(err)
	}
	if opts.MaxRequests != 500 || opts.MaxRequestsPerHost != 50 {
		t.Fatalf("config fold = %d/%d", opts.MaxRequests, opts.MaxRequestsPerHost)
	}
	opts = types.DefaultOptions()
	opts.MaxRequests = 0 // typed --max-requests 0: unlimited, over the config
	if err := ApplyScanPace(settings, opts, ExplicitPace{MaxRequests: true}); err != nil {
		t.Fatal(err)
	}
	if opts.MaxRequests != 0 || opts.MaxRequestsPerHost != 50 {
		t.Fatalf("explicit = %d/%d, want 0/50", opts.MaxRequests, opts.MaxRequestsPerHost)
	}
	bad := paceSettings(func(p *config.ScanningPaceConfig) { p.MaxRequests = -1 })
	if err := ApplyScanPace(bad, types.DefaultOptions(), ExplicitPace{}); err == nil {
		t.Fatal("a negative scanning_pace.max_requests must be rejected")
	}
}

// targetBudgetUsed counts a crawl that drained inside its grace window as having
// used its budget, but not one cut short by the phase ceiling.
func TestTargetBudgetUsed(t *testing.T) {
	parent := context.Background()
	target, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if !targetBudgetUsed(target, parent, 5*time.Second) {
		t.Fatal("returned within the grace of its own deadline: want used")
	}
	if targetBudgetUsed(target, parent, time.Second) {
		t.Fatal("returned with more than the grace left: want not used")
	}
	ceiling, cancelCeiling := context.WithTimeout(parent, 2*time.Second)
	defer cancelCeiling()
	inherited, cancelInherited := context.WithTimeout(ceiling, time.Minute)
	defer cancelInherited()
	if targetBudgetUsed(inherited, ceiling, 5*time.Second) {
		t.Fatal("the phase ceiling's deadline is not the target's budget")
	}
	if !deadlineWithin(ceiling, 5*time.Second) || deadlineWithin(parent, time.Hour) {
		t.Fatal("deadlineWithin")
	}
}
