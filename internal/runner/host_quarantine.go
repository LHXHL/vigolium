package runner

import (
	"fmt"
	"sort"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// newHostErrorCache builds the scan's dead-host breaker, or returns nil when
// --max-host-error is off. The threshold is --max-host-error; the cooldowns and
// the dead-after count come from scanning_strategy.http.host_errors, and a lost
// probe is re-admitted after twice the request timeout.
//
// phase names the phase a transition happened in, for the event; it may be nil.
func newHostErrorCache(opts *types.Options, settings *config.Settings, phase func() string) *hosterrors.Cache {
	if !opts.ShouldUseHostError() {
		return nil
	}
	cfg := hosterrors.Config{}
	if settings != nil {
		cfg = settings.ScanningStrategy.HTTP.HostErrors.BreakerConfig()
	}
	cfg.MaxHostError = opts.MaxHostError
	cfg.MaxHostsCount = hosterrors.DefaultMaxHostsCount
	if opts.Timeout > 0 {
		cfg.ProbeTTL = 2 * opts.Timeout
	}
	cache := hosterrors.NewWithConfig(cfg)
	cache.SetVerbose(opts.Verbose)
	cache.SetObserver(func(tr hosterrors.Transition) { emitHostTransition(tr, phase) })
	return cache
}

// emitHostTransition maps a breaker transition onto the host.* events. A failed
// probe that re-opens the breaker is not an event: the host was quarantined
// before and still is.
func emitHostTransition(tr hosterrors.Transition, phase func() string) {
	if !scanevents.On() {
		return
	}
	ev := scanevents.Event{Host: tr.Key}
	if phase != nil {
		ev.Phase = phase()
	}
	switch {
	case tr.From == hosterrors.StateClosed && tr.To == hosterrors.StateOpen:
		ev.Type = scanevents.TypeHostQuarantined
		ev.Detail = fmt.Sprintf("%s after %d consecutive errors; re-probe in %s",
			http.ClassifyTransportError(tr.Err), tr.Errors, tr.Cooldown)
	case tr.To == hosterrors.StateClosed:
		ev.Type = scanevents.TypeHostRecovered
		ev.Detail = fmt.Sprintf("probe succeeded after %d failed probes", tr.Trips)
	case tr.To == hosterrors.StateDead:
		ev.Type = scanevents.TypeHostDead
		ev.Detail = fmt.Sprintf("%s; %d failed probes, no further requests this scan",
			http.ClassifyTransportError(tr.Err), tr.Trips)
	default:
		return
	}
	if tr.Err != nil {
		ev.Message = tr.Err.Error()
	}
	scanevents.Emit(ev)
}

// currentPhaseName is the phase source for the runner's breaker events.
func (r *Runner) currentPhaseName() string {
	if t := r.currentPhase.Load(); t != nil {
		return t.phase
	}
	return ""
}

// noteQuarantineSkips folds one executor run's quarantine skips into the phase:
// the phase is partial (targets_unreachable), and each host lands on the phase
// outcome's unreachable list with its skipped_quarantined count.
func (t *phaseTracker) noteQuarantineSkips(rep core.ExecutionReport) {
	if t == nil || rep.SkippedQuarantined == 0 {
		return
	}
	t.markPartial(database.ReasonTargetsUnreachable)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.quarantined == nil {
		t.quarantined = make(map[string]core.QuarantinedHost)
	}
	for _, h := range rep.QuarantinedHosts {
		prev := t.quarantined[h.Host]
		h.Items += prev.Items
		t.quarantined[h.Host] = h
	}
}

// fillQuarantined puts the phase's quarantined hosts on out.Targets.Unreachable,
// Code being the transport class that tripped the breaker. Called with t.mu held.
func (t *phaseTracker) fillQuarantined(out *database.PhaseOutcome) {
	if len(t.quarantined) == 0 {
		return
	}
	hosts := make([]string, 0, len(t.quarantined))
	for h := range t.quarantined {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if out.Targets == nil {
		out.Targets = &database.TargetTally{}
	}
	for _, h := range hosts {
		q := t.quarantined[h]
		code := q.Class
		if code == "" {
			code = http.TransportErrOther
		}
		out.Targets.AddUnreachable(database.TargetIssue{
			Target: h,
			Code:   code,
			Detail: fmt.Sprintf("quarantined (%s): skipped_quarantined=%d", q.State, q.Items),
		})
	}
}
