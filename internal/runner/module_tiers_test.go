package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestIntensityTierCeiling(t *testing.T) {
	cases := map[string]int{
		"":         modules.TierRankIntrusive, // default (balanced)
		"balanced": modules.TierRankIntrusive,
		"standard": modules.TierRankIntrusive,
		"quick":    modules.TierRankModerate,
		"lite":     modules.TierRankModerate,
		"deep":     modules.TierRankIntrusive,
		"full":     modules.TierRankIntrusive,
		"DEEP":     modules.TierRankIntrusive,
		"unknown":  modules.TierRankIntrusive, // unknown falls back to balanced
	}
	for in, want := range cases {
		if got := intensityTierCeiling(in); got != want {
			t.Errorf("intensityTierCeiling(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLoginCredsIntensityGating(t *testing.T) {
	cases := []struct {
		intensity string
		enabled   bool
		full      bool
	}{
		{"", true, false},         // default → balanced: on, minimal
		{"balanced", true, false}, // balanced: on, minimal
		{"standard", true, false},
		{"deep", true, true}, // deep: on, full
		{"full", true, true},
		{"DEEP", true, true}, // case-insensitive
		{"quick", false, false},
		{"lite", false, false},
		{"unknown", true, false}, // unknown → balanced
	}
	for _, c := range cases {
		enabled, full := loginCredsPolicy(c.intensity)
		if enabled != c.enabled || full != c.full {
			t.Errorf("loginCredsPolicy(%q) = (%v, %v), want (%v, %v)",
				c.intensity, enabled, full, c.enabled, c.full)
		}
	}
}

// stubActive is a minimal ActiveModule used to test tier filtering without
// pulling in the real registry.
type tierStubActive struct {
	modules.ActiveModule
	id   string
	tags []string
}

func (s tierStubActive) ID() string     { return s.id }
func (s tierStubActive) Tags() []string { return s.tags }

func TestFilterActiveModulesByTier(t *testing.T) {
	mods := []modules.ActiveModule{
		tierStubActive{id: "untagged", tags: []string{"xss"}},
		tierStubActive{id: "light", tags: []string{"light"}},
		tierStubActive{id: "moderate", tags: []string{"moderate"}},
		tierStubActive{id: "heavy", tags: []string{"heavy"}},
		tierStubActive{id: "intrusive", tags: []string{"intrusive"}},
	}
	r := &Runner{}

	ids := func(in []modules.ActiveModule) []string {
		out := make([]string, len(in))
		for i, m := range in {
			out[i] = m.ID()
		}
		return out
	}

	// quick ceiling = moderate: drops heavy + intrusive, keeps untagged.
	got := ids(r.filterActiveModulesByTier(mods, modules.TierRankModerate))
	want := []string{"untagged", "light", "moderate"}
	if !equalStrings(got, want) {
		t.Errorf("quick ceiling = %v, want %v", got, want)
	}

	// heavy ceiling: drops only intrusive (no intensity maps here anymore, but
	// the filter must still honor an explicit heavy ceiling correctly).
	got = ids(r.filterActiveModulesByTier(mods, modules.TierRankHeavy))
	want = []string{"untagged", "light", "moderate", "heavy"}
	if !equalStrings(got, want) {
		t.Errorf("heavy ceiling = %v, want %v", got, want)
	}

	// balanced/deep ceiling = intrusive: keeps everything.
	got = ids(r.filterActiveModulesByTier(mods, modules.TierRankIntrusive))
	if len(got) != len(mods) {
		t.Errorf("intrusive ceiling dropped modules: %v", got)
	}
}

func TestHygieneModulesEnabled(t *testing.T) {
	cases := map[string]bool{
		"":         false, // default (balanced)
		"balanced": false,
		"standard": false,
		"quick":    false,
		"lite":     false,
		"deep":     true,
		"full":     true,
		"DEEP":     true,  // case-insensitive
		" deep ":   true,  // whitespace-tolerant
		"unknown":  false, // unknown falls back to balanced
	}
	for in, want := range cases {
		if got := hygieneModulesEnabled(in); got != want {
			t.Errorf("hygieneModulesEnabled(%q) = %v, want %v", in, got, want)
		}
	}
}

// The config knob overrides the intensity default in both directions; unset
// falls through to the intensity.
func TestResolveHygieneModules(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name      string
		intensity string
		cfg       *bool
		want      bool
	}{
		{"balanced, unset", "balanced", nil, false},
		{"deep, unset", "deep", nil, true},
		{"balanced, forced on", "balanced", &yes, true},
		{"deep, forced off", "deep", &no, false},
		{"quick, forced on", "quick", &yes, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := config.DefaultSettings()
			settings.DynamicAssessment.HygieneModules = c.cfg
			r := &Runner{options: &types.Options{Intensity: c.intensity}, settings: settings}
			if got := r.resolveHygieneModules(); got != c.want {
				t.Errorf("resolveHygieneModules() = %v, want %v", got, c.want)
			}
		})
	}
}

type hygieneStubPassive struct {
	modules.PassiveModule
	id   string
	tags []string
}

func (s hygieneStubPassive) ID() string     { return s.id }
func (s hygieneStubPassive) Tags() []string { return s.tags }

func TestFilterHygieneModules(t *testing.T) {
	r := &Runner{}

	active := []modules.ActiveModule{
		tierStubActive{id: "sqli", tags: []string{"injection", "moderate"}},
		tierStubActive{id: "tls-protocol-cipher-audit", tags: []string{"tls", "hygiene", "moderate"}},
	}
	got := make([]string, 0)
	for _, m := range r.filterActiveHygieneModules(active) {
		got = append(got, m.ID())
	}
	if !equalStrings(got, []string{"sqli"}) {
		t.Errorf("active filter = %v, want [sqli]", got)
	}

	passive := []modules.PassiveModule{
		hygieneStubPassive{id: "secret-detect", tags: []string{"secrets", "light"}},
		hygieneStubPassive{id: "security-headers-missing", tags: []string{"header-security", "HYGIENE", "light"}},
	}
	got = got[:0]
	for _, m := range r.filterPassiveHygieneModules(passive) {
		got = append(got, m.ID())
	}
	if !equalStrings(got, []string{"secret-detect"}) {
		t.Errorf("passive filter = %v, want [secret-detect]", got)
	}
}

// `--module-tag hygiene` resolves to exact IDs for the active category but
// leaves passive on the "all" sentinel, so the gate must recognize an explicit
// selection that names a hygiene module — otherwise the twelve passive members
// of the family are dropped by the very flag that asked for them.
func TestSelectsHygieneModule(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want bool
	}{
		{"nil", nil, false},
		{"all sentinel", []string{"all"}, false},
		{"unrelated ids", []string{"sqli-error-based", "xss-stored"}, false},
		{"active hygiene id", []string{"tls-protocol-cipher-audit"}, true},
		{"passive hygiene id", []string{"security-headers-missing"}, true},
		{"mixed", []string{"sqli-error-based", "csp-weakness-audit"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := selectsHygieneModule(c.ids); got != c.want {
				t.Errorf("selectsHygieneModule(%v) = %v, want %v", c.ids, got, c.want)
			}
		})
	}
}

// The shipped hardening-advisory family. Pinned here because the gate is a
// behavior change an operator sees in their report: adding a module to this list
// silently removes its findings from every default-intensity scan, so the set
// must be a deliberate edit rather than a stray tag. Each member reports a
// missing best-practice control, and nothing downstream reads its output.
func TestHygieneFamilyMembership(t *testing.T) {
	want := map[string]bool{
		"security-headers-missing":     true,
		"permissions-policy-detect":    true,
		"cross-origin-isolation-audit": true,
		"subresource-integrity-detect": true,
		"password-autocomplete-detect": true,
		"tls-protocol-cipher-audit":    true,
		"hsts-preload-audit":           true,
		"csp-weakness-audit":           true,
		"cors-vary-origin-missing":     true,
		"cookie-security-detect":       true,
		"mixed-content-detect":         true,
		"reverse-tabnabbing-detect":    true,
		"content-type-mismatch":        true,
		"express-session-audit":        true,
	}

	tagged := make(map[string]bool)
	for _, m := range modules.GetActiveModules() {
		if modules.IsHygieneModule(m.Tags()) {
			tagged[m.ID()] = true
		}
	}
	for _, m := range modules.GetPassiveModules() {
		if modules.IsHygieneModule(m.Tags()) {
			tagged[m.ID()] = true
		}
	}

	for id := range want {
		if !tagged[id] {
			t.Errorf("module %q is missing the %q tag — it will keep firing at the default intensity", id, modules.TagHygiene)
		}
	}
	for id := range tagged {
		if !want[id] {
			t.Errorf("module %q is newly tagged %q — its findings now disappear below --intensity deep; add it to this list if that is intended",
				id, modules.TagHygiene)
		}
	}
}

// The hygiene family must not swallow modules whose Info/Low output feeds the
// rest of the pipeline (tech tags, surface scoring, active-module targeting), nor
// clickjacking-detect, which stays on at Medium.
func TestHygieneFamilyExcludesPipelineInputs(t *testing.T) {
	mustRun := []string{
		"surface-scoring",
		"endpoint-classifier",
		"input-reflection-detect",
		"software-version-header",
		"clickjacking-detect",
		"secret-detect",
		"sourcemap-detect",
	}

	byID := make(map[string]modules.Module)
	for _, m := range modules.GetActiveModules() {
		byID[m.ID()] = m
	}
	for _, m := range modules.GetPassiveModules() {
		byID[m.ID()] = m
	}

	for _, id := range mustRun {
		m, ok := byID[id]
		if !ok {
			t.Errorf("module %q not found in the registry", id)
			continue
		}
		if modules.IsHygieneModule(m.Tags()) {
			t.Errorf("module %q must not be tagged %q — it runs at every intensity; tags=%v",
				id, modules.TagHygiene, m.Tags())
		}
	}
}

// End-to-end over the real registry: the selection path must drop the family at
// the default intensity, keep it at deep, and honor every documented escape
// hatch. The unit tests above pin each decision; this pins that they are wired
// into getModulesToExecute (both categories, in the right order relative to the
// "all"-only rule).
func TestGetModulesToExecute_HygieneGate(t *testing.T) {
	forceOn := true

	countHygiene := func(active []modules.ActiveModule, passive []modules.PassiveModule) int {
		n := 0
		for _, m := range active {
			if modules.IsHygieneModule(m.Tags()) {
				n++
			}
		}
		for _, m := range passive {
			if modules.IsHygieneModule(m.Tags()) {
				n++
			}
		}
		return n
	}

	all := []string{"all"}
	tagResolved := modules.ResolveModuleTags([]string{modules.TagHygiene})
	if len(tagResolved) == 0 {
		t.Fatal("no modules carry the hygiene tag")
	}

	cases := []struct {
		name           string
		intensity      string
		activeIDs      []string
		passiveIDs     []string
		cfg            *bool
		wantSuppressed bool
	}{
		{"balanced suppresses", "balanced", all, all, nil, true},
		{"quick suppresses", "quick", all, all, nil, true},
		{"deep keeps", "deep", all, all, nil, false},
		{"config forces on at balanced", "balanced", all, all, &forceOn, false},
		// --module-tag hygiene: active narrows to exact IDs, passive stays "all".
		{"module-tag hygiene keeps both sides", "balanced", tagResolved, all, nil, false},
		// --module-id <hygiene id>: both categories narrow to exact IDs.
		{"module-id keeps", "balanced", []string{"security-headers-missing"}, []string{"security-headers-missing"}, nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := config.DefaultSettings()
			settings.DynamicAssessment.HygieneModules = c.cfg
			r := &Runner{
				options: &types.Options{
					Intensity:      c.intensity,
					Modules:        c.activeIDs,
					PassiveModules: c.passiveIDs,
				},
				settings: settings,
			}
			active, passive := r.getModulesToExecute()
			got := countHygiene(active, passive)
			if c.wantSuppressed && got != 0 {
				t.Errorf("expected the hygiene family suppressed, still got %d module(s)", got)
			}
			if !c.wantSuppressed && got == 0 {
				t.Error("expected the hygiene family to run, got none")
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The costliest modules in the registry must be tagged so that --intensity quick
// actually drops them. Measured on a real 1.8s-RTT target, these four dominated
// dynamic-assessment wall clock (input-behavior-probe alone: 22h58m aggregate
// across 452 invocations, ~3m03s each) while producing zero findings on that run.
// Tagged "moderate" they survived even the quick ceiling, which made a "quick"
// scan anything but.
//
// This pins the tier only. It deliberately does NOT assert they are dropped at
// balanced/deep — heavy (rank 3) is below the intrusive ceiling (rank 4), so the
// default scan still runs all four. Retagging trades quick-scan coverage for
// quick-scan speed and changes nothing else.
func TestCostliestModulesAreHeavyTier(t *testing.T) {
	costly := []string{
		"input-behavior-probe",
		"reflected-ssti",
		"suspect-transform",
		"smart-behavior-detection",
		"ssti-blind",
	}

	byID := make(map[string]modules.ActiveModule)
	for _, m := range modules.GetActiveModules() {
		byID[m.ID()] = m
	}

	quick := intensityTierCeiling("quick")
	balanced := intensityTierCeiling("balanced")

	for _, id := range costly {
		m, ok := byID[id]
		if !ok {
			t.Errorf("module %q not found in the active registry", id)
			continue
		}
		rank := modules.ModuleTierRank(m.Tags())
		if rank != modules.TierRankHeavy {
			t.Errorf("module %q tier rank = %d, want heavy (%d); tags=%v",
				id, rank, modules.TierRankHeavy, m.Tags())
		}
		if rank <= quick {
			t.Errorf("module %q (rank %d) must be dropped by the quick ceiling %d", id, rank, quick)
		}
		if rank > balanced {
			t.Errorf("module %q (rank %d) must still run at the balanced ceiling %d", id, rank, balanced)
		}
	}
}
