package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestNewHostErrorCache_OffWhenMaxHostErrorZero(t *testing.T) {
	opts := types.DefaultOptions()
	opts.MaxHostError = 0
	if c := newHostErrorCache(opts, nil, nil); c != nil {
		t.Fatal("--max-host-error 0 must disable the breaker")
	}
}

// The runner's breaker emits host.quarantined when a host trips, tagged with
// the phase it tripped in.
func TestNewHostErrorCache_EmitsQuarantined(t *testing.T) {
	buf := withEventStream(t)
	opts := types.DefaultOptions()
	opts.MaxHostError = 2
	settings := &config.Settings{}
	settings.ScanningStrategy.HTTP.HostErrors = config.HostErrorsConfig{Cooldown: "45s"}

	c := newHostErrorCache(opts, settings, func() string { return "dynamic-assessment" })
	defer c.Close()
	refused := errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
	c.MarkFailed("dead.example:443", refused, false)
	if got := eventsOfType(t, buf, scanevents.TypeHostQuarantined); len(got) != 0 {
		t.Fatalf("quarantined below the threshold: %v", got)
	}
	c.MarkFailed("dead.example:443", refused, false)

	got := eventsOfType(t, buf, scanevents.TypeHostQuarantined)
	if len(got) != 1 {
		t.Fatalf("host.quarantined events = %d, want 1", len(got))
	}
	ev := got[0]
	if ev["host"] != "dead.example:443" || ev["phase"] != "dynamic-assessment" {
		t.Errorf("event = %v", ev)
	}
	if want := "refused after 2 consecutive errors; re-probe in 45s"; ev["detail"] != want {
		t.Errorf("detail = %q, want %q", ev["detail"], want)
	}
}

func TestEmitHostTransition_RecoveredAndDead(t *testing.T) {
	buf := withEventStream(t)
	emitHostTransition(hosterrors.Transition{Key: "h:80", From: hosterrors.StateHalfOpen, To: hosterrors.StateClosed, Trips: 1}, nil)
	emitHostTransition(hosterrors.Transition{Key: "h:80", From: hosterrors.StateHalfOpen, To: hosterrors.StateOpen, Trips: 1, Cooldown: time.Minute, Err: errors.New("i/o timeout")}, nil)
	emitHostTransition(hosterrors.Transition{Key: "h:81", From: hosterrors.StateHalfOpen, To: hosterrors.StateDead, Trips: 5, Err: errors.New("connection refused")}, nil)

	if got := eventsOfType(t, buf, scanevents.TypeHostRecovered); len(got) != 1 || got[0]["host"] != "h:80" {
		t.Errorf("host.recovered = %v", got)
	}
	if got := eventsOfType(t, buf, scanevents.TypeHostQuarantined); len(got) != 0 {
		t.Errorf("a re-opened breaker is not a new quarantine: %v", got)
	}
	dead := eventsOfType(t, buf, scanevents.TypeHostDead)
	if len(dead) != 1 || dead[0]["host"] != "h:81" {
		t.Fatalf("host.dead = %v", dead)
	}
	if want := "refused; 5 failed probes, no further requests this scan"; dead[0]["detail"] != want {
		t.Errorf("dead detail = %q, want %q", dead[0]["detail"], want)
	}
}

// Items an executor dropped for a quarantined host make the phase partial with
// targets_unreachable, and the host lands on the outcome's unreachable list with
// its skipped_quarantined count, summed across runs.
func TestPhaseOutcomeReportsQuarantineSkips(t *testing.T) {
	r := &Runner{}
	tr := r.beginPhase(context.Background(), "dynamic-assessment", nil)
	for range 2 {
		tr.noteExecution(core.ExecutionReport{
			SkippedQuarantined: 3,
			QuarantinedHosts: []core.QuarantinedHost{
				{Host: "dead.example:443", Items: 3, State: "dead", Class: http.TransportErrRefused},
			},
		})
	}
	tr.noteExecution(core.ExecutionReport{}) // a clean run adds nothing

	out := tr.finish(context.Background(), nil)
	if out.State != database.PhasePartial {
		t.Errorf("state = %s, want partial", out.State)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != database.ReasonTargetsUnreachable {
		t.Errorf("reasons = %v, want [%s]", out.Reasons, database.ReasonTargetsUnreachable)
	}
	if out.Targets == nil || len(out.Targets.Unreachable) != 1 {
		t.Fatalf("targets = %+v, want one unreachable host", out.Targets)
	}
	want := database.TargetIssue{Target: "dead.example:443", Code: "refused", Detail: "quarantined (dead): skipped_quarantined=6"}
	if got := out.Targets.Unreachable[0]; got != want {
		t.Errorf("unreachable[0] = %+v, want %+v", got, want)
	}
}
