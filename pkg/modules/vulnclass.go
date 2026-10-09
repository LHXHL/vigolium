package modules

import (
	"sort"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Vulnerability classes for VulnClassifier, re-exported from modkit (where
// module packages can import them without a cycle). One finding per
// (location, parameter, class) is the goal: once a module of a class reports a
// parameter, the other modules of that class skip it. --no-param-dedup turns
// the skip off for audit runs.
const (
	VulnClassSQLi          = modkit.VulnClassSQLi
	VulnClassNoSQLi        = modkit.VulnClassNoSQLi
	VulnClassCmdi          = modkit.VulnClassCmdi
	VulnClassCodeInjection = modkit.VulnClassCodeInjection
	VulnClassSSTI          = modkit.VulnClassSSTI
	VulnClassCSTI          = modkit.VulnClassCSTI
	VulnClassSSRF          = modkit.VulnClassSSRF
	VulnClassLFI           = modkit.VulnClassLFI
	VulnClassXSS           = modkit.VulnClassXSS
	VulnClassXSSStored     = modkit.VulnClassXSSStored
	VulnClassCRLF          = modkit.VulnClassCRLF
	VulnClassOpenRedirect  = modkit.VulnClassOpenRedirect
	VulnClassXXE           = modkit.VulnClassXXE
	VulnClassLDAP          = modkit.VulnClassLDAP
	VulnClassXPath         = modkit.VulnClassXPath
	VulnClassSSI           = modkit.VulnClassSSI
	VulnClassSMTPHeader    = modkit.VulnClassSMTPHeader
	VulnClassESI           = modkit.VulnClassESI
)

// knownVulnClasses is the closed set a VulnClass() return value must belong
// to (enforced by the registry contract test).
var knownVulnClasses = map[string]struct{}{
	VulnClassSQLi: {}, VulnClassNoSQLi: {}, VulnClassCmdi: {}, VulnClassCodeInjection: {},
	VulnClassSSTI: {}, VulnClassCSTI: {}, VulnClassSSRF: {}, VulnClassLFI: {},
	VulnClassXSS: {}, VulnClassXSSStored: {}, VulnClassCRLF: {}, VulnClassOpenRedirect: {},
	VulnClassXXE: {}, VulnClassLDAP: {}, VulnClassXPath: {}, VulnClassSSI: {},
	VulnClassSMTPHeader: {}, VulnClassESI: {},
}

// IsKnownVulnClass reports whether class is one of the VulnClass* constants.
func IsKnownVulnClass(class string) bool {
	_, ok := knownVulnClasses[class]
	return ok
}

// KnownVulnClasses returns the VulnClass* constants, sorted.
func KnownVulnClasses() []string {
	out := make([]string, 0, len(knownVulnClasses))
	for c := range knownVulnClasses {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Class cost ranks for ClassPrioritized, re-exported from modkit.
const (
	ClassCostInBand  = modkit.ClassCostInBand
	ClassCostBoolean = modkit.ClassCostBoolean
	ClassCostTiming  = modkit.ClassCostTiming
	ClassCostBrowser = modkit.ClassCostBrowser
	ClassCostOAST    = modkit.ClassCostOAST
)

// ClassPrioritized is an optional interface for VulnClassifier modules that
// rank themselves within their vuln class. Lower runs earlier: the executor
// reorders modules of one class so cheap, high-confidence techniques
// (error/in-band < boolean < timing < OAST) are dispatched first and claim the
// parameter before the slow ones run. It never moves a module ahead of a
// module of a different class; see ModuleClassPriority for the default.
type ClassPrioritized interface {
	ClassPriority() int
}

// ModuleClassPriority returns m's rank within its vuln class: ClassPriority()
// when declared, otherwise the intensity tier rank scaled onto the ClassCost*
// range (light=10, moderate=20, heavy=30, intrusive=40, untagged=0).
func ModuleClassPriority(m Module) int {
	if cp, ok := m.(ClassPrioritized); ok {
		return cp.ClassPriority()
	}
	return ModuleTierRank(m.Tags()) * 10
}

// ModuleVulnClass returns m's declared vuln class, or "" when m does not
// implement VulnClassifier.
func ModuleVulnClass(m Module) string {
	if vc, ok := m.(VulnClassifier); ok {
		return vc.VulnClass()
	}
	return ""
}

// OrderWithinVulnClass reorders mods in place so that, among modules sharing a
// vuln class, lower ModuleClassPriority comes first. Each class keeps exactly
// the slots its members already occupied, so modules of other classes (and
// unclassified ones) never move; ties keep their current relative order.
// Call it after any primary ordering (e.g. Prioritized) has been applied.
func OrderWithinVulnClass(mods []ActiveModule) {
	slots := make(map[string][]int)
	for i, m := range mods {
		if c := ModuleVulnClass(m); c != "" {
			slots[c] = append(slots[c], i)
		}
	}
	for _, idx := range slots {
		if len(idx) < 2 {
			continue
		}
		members := make([]ActiveModule, len(idx))
		for k, i := range idx {
			members[k] = mods[i]
		}
		sort.SliceStable(members, func(a, b int) bool {
			return ModuleClassPriority(members[a]) < ModuleClassPriority(members[b])
		})
		for k, i := range idx {
			mods[i] = members[k]
		}
	}
}
