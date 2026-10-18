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
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// preflightRunner builds a Runner with a real shared requester, the way
// RunNativeScan hands it to runPreflight. Silent, so tests print nothing.
//
// tune runs BEFORE the requester is built: the redirect policy is baked into
// the client at NewRequester (ResolveRedirectMode runs once, there), so a test
// that varies it cannot set it afterwards.
func preflightRunner(t *testing.T, tune ...func(*types.Options)) (*Runner, *phaseInfra) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	for _, f := range tune {
		f(opts)
	}
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

// countingServer counts the requests that reach the root, so a test can tell
// "the seed answered" apart from "something answered for it". One counting rule
// for every stub below, so the "requested N times" assertions cannot drift.
func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hits.Add(1)
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// redirectTo serves a 301 to dest from every path.
func redirectTo(t *testing.T, dest string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	return countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest, http.StatusMovedPermanently)
	})
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
	return countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/x">x</a></body></html>`))
	})
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

// A target that answers a redirect has ANSWERED, whatever is at the other end.
// Following meant the verdict belonged to the last hop: a 301 pointing at a
// dead host reported the TARGET as unreachable and aborted the whole scan
// before a phase ran.
func TestPreflightSeedAnswersRedirect(t *testing.T) {
	live, liveHits := countingRoot(t)
	for _, tc := range []struct {
		name string
		dest string
	}{
		// The field shape: a public redirector whose destination no longer
		// resolves. Asserted on `reached` only - an offline sandbox may classify
		// the lookup as `other` rather than `dns`.
		{"destination does not resolve", "http://preflight-dest.invalid/"},
		// The same conclusion with no resolver involved at all, so this one can
		// never flake on a DNS answer somebody's network invents.
		{"destination refuses", closedTargetURL(t)},
		// Symptom two: the kept bytes must be the seed's own 3xx, and the live
		// destination must not be requested at all.
		{"destination is live", live.URL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := liveHits.Load()
			srv, hits := redirectTo(t, tc.dest)
			r, infra := preflightRunner(t)
			admitted := []string{srv.URL + "/"}
			o := admissionOutcome(TargetAdmission{Admitted: admitted})

			if err := r.runPreflight(context.Background(), infra, admitted, &o); err != nil {
				t.Fatalf("runPreflight: %v (the target answered a 301)", err)
			}
			if len(o.Reasons) != 0 {
				t.Errorf("reasons = %v, want none", o.Reasons)
			}
			tally := o.Targets
			if tally.Reached != 1 || !tally.ReachabilityChecked || len(tally.Unreachable) != 0 {
				t.Fatalf("tally = %+v, want 1 reached and nothing unreachable", tally)
			}
			if _, stop := r.scanOutcome.snapshot(); stop != "" {
				t.Errorf("stop reason %q set for a target that answered", stop)
			}
			probe := r.preflightFor(srv.URL + "/")
			if probe == nil || !probe.reached {
				t.Fatalf("preflight answer = %+v", probe)
			}
			if got := httpmsg.GetStatusCode(probe.resp); got != http.StatusMovedPermanently {
				t.Errorf("kept status = %d, want 301 (the seed's own answer)", got)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("seed requested %d times, want 1", got)
			}
			if got := liveHits.Load() - before; got != 0 {
				t.Errorf("destination requested %d times, want 0", got)
			}
		})
	}
}

// --redirect-mode is a recording policy, not a reachability one. It used to
// decide whether a scan started at all: this target answered under same-apex
// and did not under any.
func TestPreflightRedirectModesAgree(t *testing.T) {
	for _, mode := range vighttp.RedirectModes {
		t.Run(mode, func(t *testing.T) {
			srv, _ := redirectTo(t, closedTargetURL(t))
			r, infra := preflightRunner(t, func(o *types.Options) { o.RedirectMode = mode })
			admitted := []string{srv.URL + "/"}
			o := admissionOutcome(TargetAdmission{Admitted: admitted})

			if err := r.runPreflight(context.Background(), infra, admitted, &o); err != nil {
				t.Fatalf("runPreflight under --redirect-mode %s: %v", mode, err)
			}
			if o.Targets.Reached != 1 {
				t.Errorf("reached = %d under %s, want 1", o.Targets.Reached, mode)
			}
		})
	}
}

// The heuristics phase classifies a redirecting root as the redirect it is,
// under the URL that served it - not as the destination's page filed under the
// seed's name - and keeps spidering, which follows the hop itself.
func TestHeuristicsRedirectRootFromPreflight(t *testing.T) {
	dest, destHits := countingRoot(t)
	srv, hits := redirectTo(t, dest.URL)
	r, infra := preflightRunner(t)
	r.options.Targets = []string{srv.URL + "/"}
	r.options.HeuristicsCheck = "basic"
	o := admissionOutcome(TargetAdmission{Admitted: r.options.Targets})

	if err := r.runPreflight(context.Background(), infra, r.options.Targets, &o); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}
	results, err := r.runHeuristicsCheckPhase(context.Background(), infra)
	if err != nil {
		t.Fatalf("heuristics: %v", err)
	}
	res := results[srv.URL+"/"]
	if res == nil || !res.Reachable {
		t.Fatalf("heuristics result = %+v, want a reachable root", res)
	}
	if res.StatusCode != http.StatusMovedPermanently || res.ContentType != "redirect" {
		t.Errorf("classified as %d/%q, want 301/redirect", res.StatusCode, res.ContentType)
	}
	if res.SkipSpidering {
		t.Error("a redirect points at content worth crawling; spidering must be retained")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("seed requested %d times, want 1 (preflight bytes reused)", got)
	}
	if got := destHits.Load(); got != 0 {
		t.Errorf("destination requested %d times, want 0", got)
	}
}

// --skip preflight must not change the verdict. The two paths into
// classifyRootResponse are preflight's cached bytes and fetchRoot's own GET;
// a root that classified differently between them would mean a flag documented
// as skipping a REQUEST was silently choosing which phases run.
func TestHeuristicsRootVerdictIgnoresPreflight(t *testing.T) {
	dest, _ := countingRoot(t)
	srv, _ := redirectTo(t, dest.URL)
	root := srv.URL + "/"

	r, infra := preflightRunner(t)
	r.options.Targets = []string{root}
	o := admissionOutcome(TargetAdmission{Admitted: r.options.Targets})
	if err := r.runPreflight(context.Background(), infra, r.options.Targets, &o); err != nil {
		t.Fatalf("runPreflight: %v", err)
	}

	withPre := probeTarget(context.Background(), infra.httpRequester, root, "basic", r.preflightFor(root))
	withoutPre := probeTarget(context.Background(), infra.httpRequester, root, "basic", nil)
	if withPre.StatusCode != withoutPre.StatusCode ||
		withPre.ContentType != withoutPre.ContentType ||
		withPre.SkipSpidering != withoutPre.SkipSpidering {
		t.Errorf("preflight path = %+v, fetchRoot path = %+v", withPre, withoutPre)
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
