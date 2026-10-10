package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/scanplan"
	"github.com/vigolium/vigolium/pkg/types"
)

// planFixture resolves options the way every entry point does (strategy →
// --only/--skip → scanning_pace) over default settings, and returns the plan.
type planFixture struct {
	strategy  string
	intensity string
	only      string
	skip      []string
	targets   []string
	configure func(*config.Settings, *types.Options)
	// afterStrategy runs where the CLI's module-selection auto-skip does:
	// after the strategy, before --only/--skip.
	afterStrategy func(*types.Options)
}

func (f planFixture) resolve(t *testing.T) (*scanplan.Plan, *types.Options, *config.Settings) {
	t.Helper()
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Intensity = f.intensity
	opts.OnlyPhase = f.only
	opts.SkipPhases = append([]string(nil), f.skip...)
	opts.Targets = f.targets
	if opts.Targets == nil {
		opts.Targets = []string{"https://app.example.test/"}
	}
	if f.configure != nil {
		f.configure(settings, opts)
	}
	ApplyScanSettingOverrides(settings, opts)
	if _, err := ApplyScanStrategy(settings, opts, StrategyRequest{Name: f.strategy}); err != nil {
		t.Fatalf("ApplyScanStrategy: %v", err)
	}
	if f.afterStrategy != nil {
		f.afterStrategy(opts)
	}
	if err := ApplyNativePhaseSelection(opts, func(on bool) { settings.DynamicAssessment.Extensions.Enabled = on }); err != nil {
		t.Fatalf("ApplyNativePhaseSelection: %v", err)
	}
	if err := ApplyScanPace(settings, opts, ExplicitPace{}); err != nil {
		t.Fatalf("ApplyScanPace: %v", err)
	}
	plan, err := ResolvePlan(context.Background(), PlanInput{
		Opts: opts, Settings: settings, StrategyName: f.strategy,
		Targets: opts.Targets, TargetsAreInput: true, DryRun: true,
	})
	if err != nil {
		t.Fatalf("ResolvePlan: %v", err)
	}
	return plan, opts, settings
}

func phaseOf(t *testing.T, p *scanplan.Plan, id NativePhase) scanplan.Phase {
	t.Helper()
	ph := p.Phase(string(id))
	if ph == nil {
		t.Fatalf("plan has no %s row: %+v", id, p.Phases)
	}
	return *ph
}

// TestResolvePlanPhasesAndProvenance pins which phases each common invocation
// runs and what the plan says turned the others off.
func TestResolvePlanPhasesAndProvenance(t *testing.T) {
	type want struct {
		on  []NativePhase
		off map[NativePhase]string // phase → disabled_by
	}
	cases := []struct {
		name string
		f    planFixture
		want want
	}{
		{
			name: "lite",
			f:    planFixture{strategy: "lite"},
			want: want{
				on: []NativePhase{PhasePreflight, PhaseHeuristicsCheck, PhaseDiscovery, PhaseDynamicAssessment},
				off: map[NativePhase]string{
					PhaseSpidering: "strategy", PhaseKnownIssueScan: "strategy", PhaseExternalHarvest: "strategy",
					PhaseProbe: "default", PhasePortSweep: "intensity", PhaseParamMining: "intensity", PhaseSeed: "gate",
				},
			},
		},
		{
			name: "balanced",
			f:    planFixture{strategy: "balanced"},
			want: want{
				on:  []NativePhase{PhaseSpidering, PhaseDiscovery, PhaseKnownIssueScan, PhaseDynamicAssessment},
				off: map[NativePhase]string{PhaseExternalHarvest: "strategy", PhaseHarvestProbe: "gate"},
			},
		},
		{
			name: "--only dast",
			f:    planFixture{strategy: "balanced", only: "dast"},
			want: want{
				on: []NativePhase{PhaseSeed, PhaseDynamicAssessment},
				off: map[NativePhase]string{
					PhaseDiscovery: "only", PhaseSpidering: "only", PhaseKnownIssueScan: "only",
					PhaseHeuristicsCheck: "only", PhasePortSweep: "only",
				},
			},
		},
		{
			name: "--skip discovery",
			f:    planFixture{strategy: "balanced", skip: []string{"discovery"}},
			want: want{
				on:  []NativePhase{PhaseSpidering, PhaseSeed, PhaseDynamicAssessment},
				off: map[NativePhase]string{PhaseDiscovery: "skip", PhaseTargetedReSpider: "gate"},
			},
		},
		{
			name: "--intensity deep",
			f:    planFixture{strategy: "deep", intensity: "deep"},
			want: want{
				on: []NativePhase{PhasePortSweep, PhaseParamMining, PhaseDiscovery, PhaseDynamicAssessment},
			},
		},
		{
			name: "--skip heuristics-check",
			f:    planFixture{strategy: "balanced", skip: []string{"heuristics"}},
			want: want{off: map[NativePhase]string{PhaseHeuristicsCheck: "skip"}},
		},
		{
			name: "--skip preflight",
			f:    planFixture{strategy: "balanced", skip: []string{"preflight"}},
			want: want{off: map[NativePhase]string{PhasePreflight: "skip"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := tc.f.resolve(t)
			for _, id := range tc.want.on {
				if ph := phaseOf(t, p, id); !ph.Enabled {
					t.Errorf("%s: want enabled, got off (%s)", id, ph.DisabledBy)
				}
			}
			for id, by := range tc.want.off {
				ph := phaseOf(t, p, id)
				if ph.Enabled || ph.DisabledBy != by {
					t.Errorf("%s: enabled=%v disabled_by=%q, want off by %q", id, ph.Enabled, ph.DisabledBy, by)
				}
			}
			// The plan rows follow the runner's execution order exactly.
			steps := BuildNativeScanPlan(tc.f.optsAfterResolve(t)).Steps
			if len(p.Phases) != len(steps)+1 || p.Phases[0].ID != string(PhasePreflight) {
				t.Fatalf("phases = %d rows, want preflight + %d steps", len(p.Phases), len(steps))
			}
			for i, s := range steps {
				if p.Phases[i+1].ID != string(s.Phase) || p.Phases[i+1].Enabled != s.Enabled {
					t.Errorf("row %d = %s/%v, plan step %s/%v", i+1, p.Phases[i+1].ID, p.Phases[i+1].Enabled, s.Phase, s.Enabled)
				}
			}
		})
	}
}

func (f planFixture) optsAfterResolve(t *testing.T) *types.Options {
	_, opts, _ := f.resolve(t)
	return opts
}

// TestResolvePlanModuleSelectionSkip: -m auto-skips known-issue-scan, and the
// plan names the module selection, not --skip.
func TestResolvePlanModuleSelectionSkip(t *testing.T) {
	p, _, _ := planFixture{strategy: "balanced", afterStrategy: func(o *types.Options) {
		o.SkipPhases = append(o.SkipPhases, "known-issue-scan")
		o.NotePhaseDisabled("known-issue-scan", "module_selection")
	}}.resolve(t)
	if ph := phaseOf(t, p, PhaseKnownIssueScan); ph.Enabled || ph.DisabledBy != "module_selection" {
		t.Errorf("known-issue-scan = %+v, want off by module_selection", ph)
	}
}

// TestResolvePlanBudgets pins the per-phase budget semantics and the spidering
// floor provenance.
func TestResolvePlanBudgets(t *testing.T) {
	p, opts, settings := planFixture{strategy: "balanced", configure: func(_ *config.Settings, o *types.Options) {
		o.ScanMaxDuration = 4 * time.Minute
	}}.resolve(t)
	_ = opts
	spider := phaseOf(t, p, PhaseSpidering).Budget
	if spider == nil || spider.Semantics != scanplan.SemanticsPerTargetCapped {
		t.Fatalf("spidering budget = %+v", spider)
	}
	// 4m × 0.1 = 24s, raised to the floor min(60s, 4m/2) = 60s.
	if spider.PerTargetMS != (60*time.Second).Milliseconds() || spider.Source != scanplan.SourceFloor {
		t.Errorf("spidering per-target = %dms source %s, want 60000ms floor", spider.PerTargetMS, spider.Source)
	}
	if spider.PerTargetMS != SpideringBudget(settings, opts).Milliseconds() {
		t.Errorf("plan per-target %dms != SpideringBudget %s", spider.PerTargetMS, SpideringBudget(settings, opts))
	}
	if spider.GraceMS != (6 * time.Second).Milliseconds() {
		t.Errorf("grace = %dms, want 6000", spider.GraceMS)
	}
	if b := phaseOf(t, p, PhaseDiscovery).Budget; b == nil || b.Semantics != scanplan.SemanticsPerTarget || b.Source != scanplan.SourceFactor {
		t.Errorf("discovery budget = %+v", b)
	}
	if b := phaseOf(t, p, PhaseDynamicAssessment).Budget; b == nil || b.Semantics != scanplan.SemanticsPhase || b.PhaseCeilingMS != (4*time.Minute).Milliseconds() {
		t.Errorf("dynamic-assessment budget = %+v", b)
	}
	if b := phaseOf(t, p, PhaseKnownIssueScan).Budget; b == nil || b.Semantics != scanplan.SemanticsPerLeg {
		t.Errorf("known-issue-scan budget = %+v", b)
	}
	if p.Budgets.ScanMaxDurationMS != (4 * time.Minute).Milliseconds() {
		t.Errorf("scan max = %d", p.Budgets.ScanMaxDurationMS)
	}
	// rate 100 × 240s: the pace ceiling headline.
	if p.Estimate.CeilingByPace == nil || *p.Estimate.CeilingByPace != 100*240 {
		t.Errorf("ceiling_by_pace = %v, want 24000", p.Estimate.CeilingByPace)
	}
}

// TestPlanModulesMatchRunner is the cross-check that keeps the plan and the
// runner from drifting: the counts are what getModulesToExecute returns for
// the same options, at every intensity.
func TestPlanModulesMatchRunner(t *testing.T) {
	for _, intensity := range []string{"quick", "balanced", "deep"} {
		for _, allowRisky := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s risky=%v", intensity, allowRisky), func(t *testing.T) {
				p, opts, settings := planFixture{strategy: "balanced", intensity: intensity, configure: func(_ *config.Settings, o *types.Options) {
					o.AllowRiskyPayloads = &allowRisky
				}}.resolve(t)
				r := &Runner{options: opts, settings: settings}
				active, passive := r.getModulesToExecute()
				if p.Modules.Active != len(active) || p.Modules.Passive != len(passive) {
					t.Errorf("plan modules %d/%d, runner %d/%d", p.Modules.Active, p.Modules.Passive, len(active), len(passive))
				}
				sel := FilterModulesForRun(opts, settings)
				if p.Modules.TierFiltered != len(sel.TierDeferred) || p.Modules.RiskGated != len(sel.RiskWithheld) || p.Modules.HygieneSuppressed != len(sel.HygieneSuppressed) {
					t.Errorf("gate counts = %d/%d/%d", p.Modules.TierFiltered, p.Modules.RiskGated, p.Modules.HygieneSuppressed)
				}
				var scoped int
				for _, n := range p.Modules.ByScope {
					scoped += n
				}
				if len(active) > 0 && scoped < len(active) {
					t.Errorf("by_scope sums to %d for %d active modules", scoped, len(active))
				}
				risky := RiskyPayloadsAllowed(opts, settings)
				if risky != p.Modules.RiskyPayloadsAllowed {
					t.Errorf("risky_payloads_allowed = %v, want %v", p.Modules.RiskyPayloadsAllowed, risky)
				}
				runsTimeBlind := false
				for _, m := range active {
					if m.ID() == "sqli-time-blind" {
						runsTimeBlind = true
					}
				}
				if !risky && runsTimeBlind && len(p.Modules.PayloadsGated) == 0 {
					t.Errorf("no payload gate reported below deep without the opt-in")
				}
				if risky && len(p.Modules.PayloadsGated) != 0 {
					t.Errorf("payload gates reported with risky payloads allowed: %+v", p.Modules.PayloadsGated)
				}
			})
		}
	}
}

// TestResolvePlanScopeAdmission: a scope that refuses every target disables
// every phase (disabled_by scope) and warns no_targets_in_scope; a partial
// refusal warns targets_out_of_scope and samples the rejection.
func TestResolvePlanScopeAdmission(t *testing.T) {
	onlyOther := func(s *config.Settings, _ *types.Options) {
		s.Scope.Host.Include = []string{"other.example.test"}
	}
	p, _, _ := planFixture{strategy: "balanced", configure: onlyOther}.resolve(t)
	if p.Targets.Admitted != 0 || p.Targets.Rejected != 1 || len(p.Targets.RejectedSample) != 1 {
		t.Fatalf("targets = %+v", p.Targets)
	}
	if len(p.EnabledPhaseIDs()) != 0 {
		t.Errorf("phases still enabled: %v", p.EnabledPhaseIDs())
	}
	if ph := phaseOf(t, p, PhaseDynamicAssessment); ph.DisabledBy != "scope" {
		t.Errorf("dynamic-assessment disabled_by = %q, want scope", ph.DisabledBy)
	}
	if !hasWarning(p, database.ReasonNoTargetsInScope) {
		t.Errorf("warnings = %+v", p.Warnings)
	}

	p, _, _ = planFixture{strategy: "balanced", configure: onlyOther,
		targets: []string{"https://other.example.test/", "https://app.example.test/"}}.resolve(t)
	if p.Targets.Admitted != 1 || p.Targets.Rejected != 1 || !hasWarning(p, database.ReasonTargetsOutOfScope) {
		t.Errorf("partial admission: targets %+v warnings %+v", p.Targets, p.Warnings)
	}
}

func hasWarning(p *scanplan.Plan, code string) bool {
	for _, w := range p.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// TestResolvePlanAuthNamesOnly: sessions are listed by name and kind, and no
// secret reaches the plan.
func TestResolvePlanAuthNamesOnly(t *testing.T) {
	p, _, _ := planFixture{strategy: "balanced", configure: func(_ *config.Settings, o *types.Options) {
		o.AuthInline = []string{"admin:Authorization:Bearer s3cr3t-token-value"}
	}}.resolve(t)
	if len(p.Auth) != 1 || p.Auth[0].Name != "admin" || p.Auth[0].Kind != "headers" || p.Auth[0].Source != "inline" || !p.Auth[0].Primary || p.Auth[0].Role != "primary" {
		t.Fatalf("auth = %+v", p.Auth)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatalf("plan leaks the session secret: %s", raw)
	}
}

// TestResolvePlanHasNoSideEffects: resolving a deep plan (fuzzing on, large
// wordlist tier) writes nothing — the embedded wordlists are sized from the
// embed FS, never materialized.
func TestResolvePlanHasNoSideEffects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wlDir := filepath.Join(home, "wordlists")
	t.Setenv(wordlistDirEnv, wlDir)

	p, _, _ := planFixture{strategy: "deep", intensity: "deep"}.resolve(t)
	if p.Discovery == nil || !p.Discovery.Fuzzing || p.Discovery.WordlistTier != config.WordlistTierLarge {
		t.Fatalf("discovery = %+v", p.Discovery)
	}
	slots := map[string]bool{}
	for _, w := range p.Discovery.Wordlists {
		slots[w.Slot] = true
		if w.Source != "embedded" || w.Lines == nil || *w.Lines == 0 {
			t.Errorf("wordlist %+v: want embedded with a line count", w)
		}
	}
	for _, s := range []string{wordlistSlotShortFile, wordlistSlotLongFile, wordlistSlotShortDir, wordlistSlotLongDir, wordlistSlotFuzz} {
		if !slots[s] {
			t.Errorf("missing wordlist slot %s", s)
		}
	}
	if _, err := os.Stat(wlDir); !os.IsNotExist(err) {
		t.Errorf("wordlist dir created by ResolvePlan (stat err %v)", err)
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Errorf("HOME written by ResolvePlan: %v", entries)
	}
}

// TestPlanWordlistRefsMatchMaterialized: the refs the plan sizes are the files
// resolveDiscoveryWordlists hands deparos, slot for slot.
func TestPlanWordlistRefsMatchMaterialized(t *testing.T) {
	t.Setenv(wordlistDirEnv, t.TempDir())
	settings := config.DefaultSettings()
	r := newWordlistRunner(&types.Options{Intensity: "deep"}, settings)
	refs, _ := r.discoveryWordlistRefs()
	w := r.resolveDiscoveryWordlists()
	bySlot := map[string]string{
		wordlistSlotShortFile: w.shortFile, wordlistSlotLongFile: w.longFile,
		wordlistSlotShortDir: w.shortDir, wordlistSlotLongDir: w.longDir,
	}
	for _, ref := range refs {
		if ref.slot == wordlistSlotFuzz {
			continue
		}
		if got := filepath.Base(bySlot[ref.slot]); got != ref.embedded {
			t.Errorf("slot %s: materialized %q, ref %q", ref.slot, got, ref.embedded)
		}
	}
}

// TestPlanEventOrderAndPersist runs a real (local) scan with the event stream
// on: scan.started (the CLI's, emitted first) is followed by scan.plan before
// any phase event, and the same plan is stored on the scan row.
func TestPlanEventOrderAndPersist(t *testing.T) {
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
	opts.OnlyPhase = "probe"
	opts.ScanUUID = "plan-order-scan"
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
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "plan.sqlite")
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
	scanevents.Emit(scanevents.Event{Type: scanevents.TypeScanStarted})

	r, err := New(opts)
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	r.SetSettings(settings)
	r.SetRepository(repo)
	if err := r.RunNativeScan(); err != nil {
		t.Fatalf("RunNativeScan: %v", err)
	}
	r.Close()

	var types_ []string
	var planEv *scanplan.Plan
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var ev scanevents.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		types_ = append(types_, ev.Type)
		if ev.Type == scanevents.TypeScanPlan {
			planEv = ev.Plan
		}
	}
	if len(types_) < 2 || types_[0] != scanevents.TypeScanStarted || types_[1] != scanevents.TypeScanPlan {
		t.Fatalf("event order = %v, want scan.started, scan.plan first", types_)
	}
	if planEv == nil || planEv.ScanUUID != opts.ScanUUID || !planEv.Phase(string(PhaseProbe)).Enabled {
		t.Fatalf("scan.plan payload = %+v", planEv)
	}

	row, err := repo.GetScanByUUID(context.Background(), opts.ScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := scanplan.Decode(row.Plan)
	if err != nil || stored == nil {
		t.Fatalf("scans.plan = %s (%v)", row.Plan, err)
	}
	if got, want := stored.EnabledPhaseIDs(), planEv.EnabledPhaseIDs(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("stored phases %v, emitted %v", got, want)
	}
}

// TestDisabledByVocabulary keeps every disabled_by the resolver can produce
// inside the documented set.
func TestDisabledByVocabulary(t *testing.T) {
	allowed := map[string]bool{"strategy": true, "only": true, "skip": true, "heuristics": true, "intensity": true,
		"module_selection": true, "default": true, "gate": true, "scope": true, "flag": true}
	var seen []string
	for _, f := range []planFixture{
		{strategy: "lite"}, {strategy: "balanced", only: "dast"}, {strategy: "balanced", skip: []string{"discovery", "spidering", "harvest-probe", "param-mining"}},
	} {
		p, _, _ := f.resolve(t)
		for _, ph := range p.Phases {
			if !ph.Enabled {
				seen = append(seen, ph.DisabledBy)
				if !allowed[ph.DisabledBy] {
					t.Errorf("%s: disabled_by %q not in the vocabulary", ph.ID, ph.DisabledBy)
				}
			}
		}
	}
	sort.Strings(seen)
	if len(seen) == 0 {
		t.Fatal("no disabled phases seen")
	}
}
