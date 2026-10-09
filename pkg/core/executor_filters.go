package core

import (
	"sort"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func filterActiveModulesByScanScope(mods []modules.ActiveModule, scope modules.ScanScope) []modules.ActiveModule {
	var result []modules.ActiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
}

func filterPassiveModulesByScanScope(mods []modules.PassiveModule, scope modules.ScanScope) []modules.PassiveModule {
	var result []modules.PassiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
}

// modulePriority returns the priority of a module. Lower values = higher priority.
// Modules implementing the Prioritized interface declare their own priority;
// others default to DefaultModulePriority (100).
func modulePriority(m modules.Module) int {
	if p, ok := m.(modules.Prioritized); ok {
		return p.Priority()
	}
	return modkit.DefaultModulePriority
}

// sortActiveByPriority sorts active modules by priority (lower = higher priority).
// Uses stable sort to preserve registration order for modules with equal priority.
func sortActiveByPriority(mods []modules.ActiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return modulePriority(mods[i]) < modulePriority(mods[j])
	})
	// Within one vuln class, dispatch cheap in-band techniques before boolean,
	// timing and OAST ones so they claim the parameter first (ParamFindings).
	modules.OrderWithinVulnClass(mods)
}

// filterNonScopeAware removes passive modules that declared themselves as
// scope-aware. Called when the current item is out of scope so that only
// modules that explicitly want all traffic (e.g., fingerprinting) still run.
func filterNonScopeAware(mods []modules.PassiveModule) []modules.PassiveModule {
	out := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if sa, ok := m.(modules.ScopeAwareModule); ok && sa.ScopeAware() {
			continue
		}
		out = append(out, m)
	}
	return out
}
