package modules

import "testing"

// riskHighModules pins the modules whose probes have side effects severe
// enough to stay off below --intensity deep unless --allow-risky-payloads is
// set. Module metadata spells the tag as a literal (it cannot import this
// package), so this test keeps the literal in sync with TagRiskHigh.
var riskHighModules = map[string]string{
	"password-reset-poisoning": "every replay sends a real password-reset email",
	"redos-probe":              "a vulnerable pattern pins a server worker per probe",
}

func TestDefaultRegistry_RiskHighModulesTagged(t *testing.T) {
	active := map[string]ActiveModule{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		active[m.ID()] = m
	}
	for id, why := range riskHighModules {
		m, ok := active[id]
		if !ok {
			t.Errorf("risk:high module %q is not registered (renamed? update riskHighModules)", id)
			continue
		}
		if !IsRiskHighModule(m.Tags()) {
			t.Errorf("module %q must carry %q: %s", id, TagRiskHigh, why)
		}
	}
}
