package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestRiskyPayloadsAllowed covers the opt-in precedence: an explicit
// --allow-risky-payloads (either value) beats config, config beats the default,
// and deep intensity always allows.
func TestRiskyPayloadsAllowed(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name      string
		intensity string
		flag      *bool
		cfg       bool
		want      bool
	}{
		{"balanced default", "balanced", nil, false, false},
		{"quick default", "quick", nil, false, false},
		{"empty intensity default", "", nil, false, false},
		{"deep default", "deep", nil, false, true},
		{"full alias", "full", nil, false, true},
		{"config on", "balanced", nil, true, true},
		{"flag on", "balanced", &yes, false, true},
		{"flag off beats config on", "balanced", &no, true, false},
		{"flag off cannot undo deep", "deep", &no, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := config.DefaultSettings()
			settings.DynamicAssessment.AllowRiskyPayloads = c.cfg
			r := &Runner{options: &types.Options{Intensity: c.intensity, AllowRiskyPayloads: c.flag}, settings: settings}
			if got := r.riskyPayloadsAllowed(); got != c.want {
				t.Errorf("riskyPayloadsAllowed() = %v, want %v", got, c.want)
			}
		})
	}
	if RiskyPayloadsAllowed(nil, nil) {
		t.Error("nil options/settings must not allow risky payloads")
	}
}

func TestFilterRiskHighModules(t *testing.T) {
	r := &Runner{}
	active := []modules.ActiveModule{
		tierStubActive{id: "sqli-time-blind", tags: []string{"injection", "heavy"}},
		tierStubActive{id: "password-reset-poisoning", tags: []string{"intrusive", modules.TagRiskHigh}},
		tierStubActive{id: "race-limit-overrun", tags: []string{"RISK:HIGH"}},
	}
	var got []string
	for _, m := range filterRiskHighModules(r, active, "Active") {
		got = append(got, m.ID())
	}
	if !equalStrings(got, []string{"sqli-time-blind"}) {
		t.Errorf("risk filter = %v, want [sqli-time-blind]", got)
	}

	passive := []modules.PassiveModule{
		hygieneStubPassive{id: "secret-detect", tags: []string{"light"}},
	}
	if out := filterRiskHighModules(r, passive, "Passive"); len(out) != 1 {
		t.Errorf("passive filter dropped an untagged module: %v", out)
	}
}

// TestGetModulesToExecute_RiskHighGate checks the gate is wired into the broad
// selection: no risk:high module survives a balanced "all" selection.
func TestGetModulesToExecute_RiskHighGate(t *testing.T) {
	for _, intensity := range []string{"balanced", "quick"} {
		r := &Runner{
			options:  &types.Options{Intensity: intensity, Modules: []string{"all"}, PassiveModules: []string{"all"}},
			settings: config.DefaultSettings(),
		}
		active, passive := r.getModulesToExecute()
		for _, m := range active {
			if modules.IsRiskHighModule(m.Tags()) {
				t.Errorf("%s broad selection kept risk:high active module %s", intensity, m.ID())
			}
		}
		for _, m := range passive {
			if modules.IsRiskHighModule(m.Tags()) {
				t.Errorf("%s broad selection kept risk:high passive module %s", intensity, m.ID())
			}
		}
	}
}
