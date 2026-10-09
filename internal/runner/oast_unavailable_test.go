package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// oastBlackhole is an interactsh server_url whose host accepts TCP connections
// and never answers.
func oastBlackhole(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "http://" + ln.Addr().String()
}

func oastRunner(serverURL string) *Runner {
	return &Runner{
		options:  &types.Options{Silent: true},
		settings: &config.Settings{OAST: config.OASTConfig{Enabled: true, ServerURL: serverURL}},
	}
}

func daPlan(enabled bool) NativeScanPlan {
	return NativeScanPlan{Steps: []NativePhaseStep{
		{Phase: PhaseDiscovery, Enabled: true},
		{Phase: PhaseDynamicAssessment, Enabled: enabled},
	}}
}

// TestOASTUnavailable_DAStartsWithinBound: an interactsh server that never
// answers must cost dynamic assessment at most the bounded wait, and the gap is
// recorded (non-stopping oast_unavailable reason, oast.unavailable event)
// rather than silently dropping every blind check.
func TestOASTUnavailable_DAStartsWithinBound(t *testing.T) {
	buf := withEventStream(t)
	r := oastRunner(oastBlackhole(t))
	infra := &phaseInfra{scanUUID: "scan-oast"}
	t.Cleanup(infra.Close)

	r.startOASTRegistration(daPlan(true), infra)
	if infra.oast == nil {
		t.Fatal("registration not started with dynamic assessment in the plan")
	}

	ctx := context.Background()
	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), nil)
	r.currentPhase.Store(tracker)

	start := time.Now()
	svc := r.awaitOAST(ctx, infra)
	if elapsed := time.Since(start); elapsed > oastReadyWait+500*time.Millisecond {
		t.Errorf("dynamic assessment waited %s for OAST, want <= %s", elapsed, oastReadyWait)
	}
	if svc != nil || infra.oast != nil {
		t.Fatal("awaitOAST handed an unregistered OAST service to the phase")
	}

	outcome := tracker.finish(ctx, nil)
	if !slices.Contains(outcome.Reasons, database.ReasonOASTUnavailable) {
		t.Errorf("phase reasons = %v, want %s", outcome.Reasons, database.ReasonOASTUnavailable)
	}
	r.scanOutcome.append(outcome)
	c := r.Completion()
	if c.Completeness != database.CompletenessPartial {
		t.Errorf("completeness = %q, want partial", c.Completeness)
	}
	if c.StopReason != database.ReasonOASTUnavailable {
		t.Errorf("stop reason = %q, want %s", c.StopReason, database.ReasonOASTUnavailable)
	}

	evs := eventsOfType(t, buf, scanevents.TypeOASTUnavailable)
	if len(evs) != 1 {
		t.Fatalf("got %d oast.unavailable events, want 1: %s", len(evs), buf.String())
	}
	if msg, _ := evs[0]["message"].(string); !strings.Contains(msg, "127.0.0.1") {
		t.Errorf("oast.unavailable message = %q, want it to name the server", msg)
	}
	if evs[0]["phase"] != string(PhaseDynamicAssessment) {
		t.Errorf("oast.unavailable phase = %v", evs[0]["phase"])
	}
}

func TestOASTReady_HandedToPhase(t *testing.T) {
	buf := withEventStream(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))
	}))
	t.Cleanup(srv.Close)

	r := oastRunner(srv.URL)
	infra := &phaseInfra{scanUUID: "scan-oast-ok"}
	t.Cleanup(infra.Close)
	r.startOASTRegistration(daPlan(true), infra)

	ctx := context.Background()
	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), nil)
	r.currentPhase.Store(tracker)

	svc := r.awaitOAST(ctx, infra)
	if svc == nil || !svc.Enabled() {
		t.Fatal("awaitOAST did not hand a registered OAST service to the phase")
	}
	outcome := tracker.finish(ctx, nil)
	if slices.Contains(outcome.Reasons, database.ReasonOASTUnavailable) {
		t.Errorf("phase reasons = %v, want no %s", outcome.Reasons, database.ReasonOASTUnavailable)
	}
	if evs := eventsOfType(t, buf, scanevents.TypeOASTUnavailable); len(evs) != 0 {
		t.Errorf("got %d oast.unavailable events for a registered service", len(evs))
	}
}

// TestOASTRegistration_OnlyWhenDAPlanned: a scan without dynamic assessment
// (discovery-only, spidering-only) never registers with an interactsh server.
func TestOASTRegistration_OnlyWhenDAPlanned(t *testing.T) {
	r := oastRunner(oastBlackhole(t))
	infra := &phaseInfra{}
	r.startOASTRegistration(daPlan(false), infra)
	if infra.oast != nil {
		infra.oast.Close()
		t.Fatal("OAST registration started for a plan without dynamic assessment")
	}

	disabled := &Runner{options: &types.Options{}, settings: &config.Settings{}}
	disabled.startOASTRegistration(daPlan(true), infra)
	if infra.oast != nil {
		t.Fatal("OAST registration started with oast.enabled: false")
	}
}
