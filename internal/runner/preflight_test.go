package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

// preflightRunner builds a Runner with a real shared requester, the way
// RunNativeScan hands it to runPreflight. Silent, so tests print nothing.
func preflightRunner(t *testing.T) (*Runner, *phaseInfra) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	req, err := vighttp.NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	r := &Runner{options: opts, scanLogger: database.NewScanLogger(nil, "")}
	return r, &phaseInfra{httpRequester: req}
}

// closedTargetURL is an http URL on a port nothing listens on.
func closedTargetURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/"
}

func countingRoot(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/x">x</a></body></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// One live and one dead target: the run goes on, the preflight outcome is
// partial with targets_unreachable, and the dead one is named with its class.
func TestPreflightPartialUnreachable(t *testing.T) {
	srv, _ := countingRoot(t)
	dead := closedTargetURL(t)
	r, infra := preflightRunner(t)
	admitted := []string{srv.URL, dead}
	o := admissionOutcome(TargetAdmission{Admitted: admitted})

	if err := r.runPreflight(context.Background(), infra, admitted, &o); err != nil {
		t.Fatalf("runPreflight: %v (one target answered, the run must go on)", err)
	}
	if !reflect.DeepEqual(o.Reasons, []string{database.ReasonTargetsUnreachable}) || o.State != database.PhasePartial {
		t.Fatalf("outcome = %+v, want partial targets_unreachable", o)
	}
	tally := o.Targets
	if tally.Reached != 1 || !tally.ReachabilityChecked || len(tally.Unreachable) != 1 {
		t.Fatalf("tally = %+v", tally)
	}
	if got := tally.Unreachable[0]; got.Target != dead || got.Code != vighttp.TransportErrRefused {
		t.Errorf("unreachable = %+v, want %s refused", got, dead)
	}
	if n, known := tally.UnreachableCount(); !known || n != 1 {
		t.Errorf("UnreachableCount = %d,%v", n, known)
	}
	if _, stop := r.scanOutcome.snapshot(); stop != "" {
		t.Errorf("stop reason %q set for a partial preflight", stop)
	}
}

// No target answered: ErrNoTargetsReachable, stop reason no_targets_reachable,
// and a completion that says so.
func TestPreflightNoneReachable(t *testing.T) {
	a, b := closedTargetURL(t), closedTargetURL(t)
	r, infra := preflightRunner(t)
	admitted := []string{a, b}
	o := admissionOutcome(TargetAdmission{Admitted: admitted})

	err := r.runPreflight(context.Background(), infra, admitted, &o)
	if !errors.Is(err, ErrNoTargetsReachable) {
		t.Fatalf("err = %v, want ErrNoTargetsReachable", err)
	}
	var typed *TargetsUnreachableError
	if !errors.As(err, &typed) || len(typed.Unreachable) != 2 {
		t.Fatalf("typed error = %+v", typed)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("message %q must say why", err.Error())
	}
	if !reflect.DeepEqual(o.Reasons, []string{database.ReasonNoTargetsReachable}) {
		t.Errorf("reasons = %v", o.Reasons)
	}
	r.scanOutcome.append(o)
	phases, stop := r.scanOutcome.snapshot()
	c := completionOf(phases, stop)
	if c.StopReason != database.ReasonNoTargetsReachable || c.Completeness != database.CompletenessPartial {
		t.Errorf("completion = %s/%s", c.Completeness, c.StopReason)
	}
}

// The heuristics probe classifies the root preflight already fetched instead of
// requesting it again: the root is hit exactly once across both.
func TestPreflightBytesReusedByHeuristics(t *testing.T) {
	srv, hits := countingRoot(t)
	r, infra := preflightRunner(t)
	r.options.Targets = []string{srv.URL}
	r.options.HeuristicsCheck = "basic"
	o := admissionOutcome(TargetAdmission{Admitted: r.options.Targets})

	if err := r.runPreflight(context.Background(), infra, r.options.Targets, &o); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}
	results, err := r.runHeuristicsCheckPhase(context.Background(), infra)
	if err != nil {
		t.Fatalf("heuristics: %v", err)
	}
	res := results[srv.URL]
	if res == nil || !res.Reachable || res.ContentType != "html" {
		t.Fatalf("heuristics result = %+v, want a reachable html root", res)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("root requested %d times, want 1 (preflight bytes reused)", got)
	}
}

// A dead root reaches heuristics as unreachable with its class, not the
// generic "request failed", and is not re-requested.
func TestHeuristicsUnreachableFromPreflight(t *testing.T) {
	dead := closedTargetURL(t)
	r, infra := preflightRunner(t)
	r.options.Targets = []string{dead}
	r.options.HeuristicsCheck = "basic"
	o := admissionOutcome(TargetAdmission{Admitted: r.options.Targets})
	_ = r.runPreflight(context.Background(), infra, r.options.Targets, &o)

	results, _ := r.runHeuristicsCheckPhase(context.Background(), infra)
	res := results[dead]
	if res == nil || res.Reachable || res.ErrClass != vighttp.TransportErrRefused {
		t.Fatalf("result = %+v, want unreachable/refused", res)
	}
	if !strings.Contains(res.Reason, "connection refused") || res.SkipSpidering {
		t.Errorf("reason = %q skip = %v", res.Reason, res.SkipSpidering)
	}
}

// Preflight is skipped by --skip preflight, for a standalone host sweep, and
// for a plan that never reaches the target.
func TestPreflightApplies(t *testing.T) {
	reaches := NativeScanPlan{Steps: []NativePhaseStep{{Phase: PhaseDynamicAssessment, Enabled: true}}}
	silent := NativeScanPlan{Steps: []NativePhaseStep{{Phase: PhaseExternalHarvest, Enabled: true, SkipsTarget: true}}}

	r := &Runner{options: &types.Options{}}
	if !r.preflightApplies(reaches) {
		t.Error("a plan that reaches the target must preflight")
	}
	if r.preflightApplies(silent) {
		t.Error("a target-silent plan must not preflight")
	}
	r.options.SkipPreflight = true
	if r.preflightApplies(reaches) {
		t.Error("--skip preflight must turn it off")
	}
	probeOnly := &Runner{options: &types.Options{ProbeEnabled: true, OnlyPhase: "probe"}}
	if probeOnly.preflightApplies(reaches) {
		t.Error("a probe-only run has its own reachability accounting")
	}
}

func TestPreflightKey(t *testing.T) {
	for in, want := range map[string]string{
		"http://a.test":         "http://a.test/",
		"http://a.test/":        "http://a.test/",
		"http://a.test/x?q=1#f": "http://a.test/x?q=1",
	} {
		if got := preflightKey(in); got != want {
			t.Errorf("preflightKey(%q) = %q, want %q", in, got, want)
		}
	}
}
