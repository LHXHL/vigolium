package runner

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// TestSpideringPhaseReportsBrowserRequests pins that the browser phases report
// the requests their captures counted. The shared requester never sees browser
// traffic, so spidering's phase.finished used to read requests_sent ≈ 0.
func TestSpideringPhaseReportsBrowserRequests(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), string(PhaseSpidering), nil)
	r.currentPhase.Store(tr)
	defer r.currentPhase.Store((*phaseTracker)(nil))

	// Two crawls of the phase share one counter pair, as the per-target and
	// session paths do.
	counters := r.trackBrowserRequests()
	var first, second spitolas.SpiderConfig
	counters.wire(&first)
	counters.wire(&second)
	first.RequestCounter.Add(30)
	first.InScopeRequestCounter.Add(12)
	second.RequestCounter.Add(10)
	second.InScopeRequestCounter.Add(8)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1: %s", len(finished), buf.String())
	}
	if got := finished[0]["requests_sent"]; got != float64(40) {
		t.Errorf("requests_sent = %v, want 40", got)
	}
	if got := finished[0]["requests_in_scope"]; got != float64(20) {
		t.Errorf("requests_in_scope = %v, want 20", got)
	}
}

// TestRequestsInScopeOnlyOnBrowserPhases pins that a phase without an in-scope
// counter omits the field rather than reporting 0.
func TestRequestsInScopeOnlyOnBrowserPhases(t *testing.T) {
	buf := withEventStream(t)

	r := &Runner{}
	tr := r.beginPhase(context.Background(), "discovery", nil)
	tr.finish(context.Background(), nil)

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 1 {
		t.Fatalf("got %d phase.finished events, want 1", len(finished))
	}
	if v, ok := finished[0]["requests_in_scope"]; ok {
		t.Fatalf("requests_in_scope = %v on a non-browser phase, want it absent", v)
	}
}

func TestBrowserRequestCountersNilSafe(t *testing.T) {
	var cfg spitolas.SpiderConfig
	var bc *browserRequestCounters
	bc.wire(&cfg)
	if cfg.RequestCounter != nil {
		t.Fatal("nil counters wired a counter")
	}
	// No running phase: registering is a no-op, counting still works.
	r := &Runner{}
	r.trackBrowserRequests().wire(&cfg)
	cfg.RequestCounter.Add(1)
}
