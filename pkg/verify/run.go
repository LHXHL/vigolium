package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// RunOptions configures Run.
type RunOptions struct {
	// Requester and Services carry the HTTP stack. Services may be nil; a
	// fresh dedup manager is used per run either way so one finding's
	// module-internal dedup never hides another's.
	Requester *http.Requester
	Services  *services.Services
	// Refetch makes a passive verify fetch a fresh response instead of
	// re-reading the stored one (the default sends nothing).
	Refetch bool
	// Timeout bounds one finding's run (0 = no bound beyond the module's own).
	Timeout time.Duration
}

// Result is one finding's verify outcome: the JSON item `finding verify -j`
// emits.
type Result struct {
	ID          int64  `json:"id"`
	FindingHash string `json:"finding_hash"`
	ModuleID    string `json:"module_id"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`

	Plan *Plan `json:"plan,omitempty"`

	// Results counts what the re-run module reported; Matched how many of
	// those are this finding.
	Results    int   `json:"results"`
	Matched    int   `json:"matched"`
	Requests   int64 `json:"requests"`
	DurationMs int64 `json:"duration_ms"`

	// Written is true once the verdict is stored on the finding; Status is the
	// status change --mark made, when it made one.
	Written bool                          `json:"written"`
	Status  *database.FindingStatusChange `json:"status_change,omitempty"`
}

// Run executes a reconstructed plan and returns the verdict. It writes
// nothing.
func Run(ctx context.Context, p *Plan, opts RunOptions) *Result {
	res := &Result{ID: p.FindingID, FindingHash: p.FindingHash, ModuleID: p.ModuleID, Plan: p}
	if p.Verdict != "" {
		res.Verdict, res.Reason = p.Verdict, p.Reason
		return res
	}
	start := time.Now()
	defer func() { res.DurationMs = time.Since(start).Milliseconds() }()

	item := p.item
	passive := p.ModuleType == database.ModuleTypePassive
	skipBaseline := passive && !opts.Refetch
	if skipBaseline && !item.HasResponse() {
		res.Verdict = database.VerdictInconclusive
		res.Reason = "the stored record has no response to analyze; pass --refetch to fetch one"
		return res
	}
	if !skipBaseline {
		// A fresh baseline: the stored response is what the target said then.
		item = httpmsg.NewHttpRequestResponse(item.Request(), nil)
		if opts.Requester == nil {
			res.Verdict, res.Reason = database.VerdictInconclusive, "no HTTP client available"
			return res
		}
	}
	p.Network = !skipBaseline

	runCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	svc := &services.Services{}
	if opts.Services != nil {
		copied := *opts.Services
		svc = &copied
	}
	dedupMgr := dedup.NewManager()
	defer dedupMgr.Close()
	svc.DedupManager = dedupMgr
	var sentBefore int64
	if svc.Egress != nil {
		sentBefore = svc.Egress.Sent()
	}

	var mu sync.Mutex
	var collected []*output.ResultEvent
	collect := func(r *output.ResultEvent) {
		mu.Lock()
		collected = append(collected, r)
		mu.Unlock()
	}
	var timeouts atomic.Int64
	cfg := core.ExecutorConfig{
		Workers:              1,
		Services:             svc,
		HTTPRequester:        opts.Requester,
		SkipBaseline:         skipBaseline,
		DisableFeedback:      true,
		TechFilterDisabled:   true,
		MaxFindingsPerModule: 0,
		ModuleTimeouts:       &timeouts,
		OnResult:             collect,
		OnCandidate:          collect,
		OnObservation:        collect,
		InsertionPointFilter: p.pointFilter(),
	}
	if opts.Timeout > 0 {
		cfg.ActiveModuleTimeout = opts.Timeout
		cfg.PassiveModuleTimeout = opts.Timeout
	}

	var active []modules.ActiveModule
	var passiveMods []modules.PassiveModule
	if passive {
		passiveMods = []modules.PassiveModule{p.module.(modules.PassiveModule)}
	} else {
		active = []modules.ActiveModule{p.module.(modules.ActiveModule)}
	}
	exec := core.NewExecutor(cfg, source.NewSingleSource(item, nil), active, passiveMods)
	exec.SetNoParamDedup(true)
	_, execErr := exec.Execute(runCtx)

	if svc.Egress != nil {
		res.Requests = svc.Egress.Sent() - sentBefore
	}
	res.Results = len(collected)
	for _, r := range collected {
		if p.matches(r) {
			res.Matched++
		}
	}

	switch {
	case res.Matched > 0:
		res.Verdict = database.VerdictConfirmed
		res.Reason = fmt.Sprintf("%s reported the finding again", p.ModuleID)
	case runCtx.Err() != nil:
		res.Verdict = database.VerdictInconclusive
		res.Reason = "timed out before the module finished"
		if errors.Is(ctx.Err(), context.Canceled) {
			res.Reason = "interrupted"
		}
	case execErr != nil:
		res.Verdict, res.Reason = database.VerdictInconclusive, "run failed: "+execErr.Error()
	case exec.Report().Responded == 0:
		res.Verdict, res.Reason = database.VerdictInconclusive, unreachableReason(exec)
	case timeouts.Load() > 0:
		res.Verdict, res.Reason = database.VerdictInconclusive, "the module timed out"
	case moduleErrors(exec, p.ModuleID) > 0:
		res.Verdict, res.Reason = database.VerdictInconclusive, "the module returned an error"
	default:
		res.Verdict = database.VerdictNotReproduced
		res.Reason = fmt.Sprintf("%s ran clean against the baseline", p.ModuleID)
		if res.Results > 0 {
			res.Reason = fmt.Sprintf("%s ran and reported %d other result(s), none of them this finding", p.ModuleID, res.Results)
		}
	}
	return res
}

func unreachableReason(exec *core.Executor) string {
	if fails := exec.BaselineFailures(); len(fails) > 0 {
		f := fails[0]
		return fmt.Sprintf("target unreachable (%s): %s", f.Class, f.Detail)
	}
	return "target unreachable: the baseline request got no response"
}

func moduleErrors(exec *core.Executor, moduleID string) int64 {
	if snap, ok := exec.ModuleMetrics()[moduleID]; ok {
		return snap.Errors
	}
	return 0
}

// pointFilter narrows the per-insertion-point stage to the plan's point.
func (p *Plan) pointFilter() func(httpmsg.InsertionPoint) bool {
	if p.InsertionPoint == nil || p.InsertionPoint.Name == "" {
		return nil
	}
	want := *p.InsertionPoint
	return func(ip httpmsg.InsertionPoint) bool {
		if want.Type != "" && !strings.EqualFold(ip.Type().String(), want.Type) {
			return false
		}
		if ip.Type() == httpmsg.INS_HEADER {
			return strings.EqualFold(ip.Name(), want.Name)
		}
		return ip.Name() == want.Name
	}
}

// matches reports whether a re-run result is the finding being verified: the
// same identity hash, or the same module, record kind, location and (for a
// point finding) parameter. A passive result without the same hash must also
// carry the same finding name, since one passive module can report several
// distinct issues on one record.
func (p *Plan) matches(r *output.ResultEvent) bool {
	f := p.finding
	if r == nil || r.ModuleID != f.ModuleID {
		return false
	}
	if kind := f.RecordKind; kind != "" && string(r.EffectiveRecordKind()) != kind {
		return false
	}
	if r.ID() == f.FindingHash {
		return true
	}
	if ip := p.InsertionPoint; ip != nil && ip.Name != "" && r.FuzzingParameter != "" && r.FuzzingParameter != ip.Name {
		return false
	}
	if p.ModuleType == database.ModuleTypePassive && r.Info.Name != f.ModuleName {
		return false
	}
	want := modkit.ParamFindingKeyFromResult(&output.ResultEvent{URL: f.URL, Request: f.Request})
	got := modkit.ParamFindingKeyFromResult(r)
	return want == "" || got == "" || want == got
}
