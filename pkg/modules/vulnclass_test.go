package modules

import (
	"testing"
)

// injectionFamilyClasses pins the vuln class of every module in the
// injection families that share a parameter-level sink. Modules of one class
// dedup each other per (location, param); keep tech-specific probes
// (log4shell-probe, struts-ognl-injection, pdf-generation-injection,
// aem-xxe) out of the generic classes.
var injectionFamilyClasses = map[string]string{
	"sqli-error-based":           VulnClassSQLi,
	"sqli-boolean-blind":         VulnClassSQLi,
	"sqli-time-blind":            VulnClassSQLi,
	"sqli-out-of-band":           VulnClassSQLi,
	"nosqli-error-based":         VulnClassNoSQLi,
	"nosqli-operator-injection":  VulnClassNoSQLi,
	"command-injection-echo":     VulnClassCmdi,
	"command-injection-timing":   VulnClassCmdi,
	"command-injection-oast":     VulnClassCmdi,
	"code-exec":                  VulnClassCodeInjection,
	"server-side-js-injection":   VulnClassCodeInjection,
	"reflected-ssti":             VulnClassSSTI,
	"ssti-detection":             VulnClassSSTI,
	"ssti-blind":                 VulnClassSSTI,
	"angular-template-injection": VulnClassCSTI,
	"csti-detection":             VulnClassCSTI,
	"ssrf-detection":             VulnClassSSRF,
	"ssrf-filter-bypass":         VulnClassSSRF,
	"ssrf-protocol-smuggling":    VulnClassSSRF,
	"ssrf-blind":                 VulnClassSSRF,
	"lfi-generic":                VulnClassLFI,
	"lfi-path-traversal":         VulnClassLFI,
	"xss-light-url-params":       VulnClassXSS,
	"xss-light-path":             VulnClassXSS,
	"xss-light-param-discovery":  VulnClassXSS,
	"xss-light-encoded":          VulnClassXSS,
	"xss-dom-confirm":            VulnClassXSS,
	"xss-stored":                 VulnClassXSSStored,
	"crlf-injection":             VulnClassCRLF,
	"response-header-injection":  VulnClassCRLF,
	"open-redirect":              VulnClassOpenRedirect,
	"open-redirect-confusion":    VulnClassOpenRedirect,
	"xxe-generic":                VulnClassXXE,
	"ldap-injection":             VulnClassLDAP,
	"xpath-injection":            VulnClassXPath,
	"ssi-injection":              VulnClassSSI,
	"smtp-header-injection":      VulnClassSMTPHeader,
	"esi-injection":              VulnClassESI,
}

// unclassifiedSinkModules test sinks a generic class would wrongly suppress.
var unclassifiedSinkModules = []string{
	"log4shell-probe", "struts-ognl-injection", "pdf-generation-injection", "aem-xxe",
}

func TestDefaultRegistry_InjectionFamiliesDeclareVulnClass(t *testing.T) {
	active := map[string]ActiveModule{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		active[m.ID()] = m
	}
	for id, want := range injectionFamilyClasses {
		m, ok := active[id]
		if !ok {
			t.Errorf("injection-family module %q is not registered (renamed? update injectionFamilyClasses)", id)
			continue
		}
		vc, ok := m.(VulnClassifier)
		if !ok {
			t.Errorf("injection-family module %q does not implement VulnClassifier", id)
			continue
		}
		if got := vc.VulnClass(); got != want {
			t.Errorf("module %q VulnClass() = %q, want %q", id, got, want)
		}
	}
	for _, id := range unclassifiedSinkModules {
		if m, ok := active[id]; ok {
			if c := ModuleVulnClass(m); c != "" {
				t.Errorf("module %q tests a tech-specific sink and must not join class %q", id, c)
			}
		}
	}
}

func TestDefaultRegistry_VulnClassIsKnownConstant(t *testing.T) {
	for _, m := range DefaultRegistry.GetActiveModules() {
		vc, ok := m.(VulnClassifier)
		if !ok {
			continue
		}
		if c := vc.VulnClass(); !IsKnownVulnClass(c) {
			t.Errorf("module %q VulnClass() = %q, not one of %v (add a VulnClass* constant)", m.ID(), c, KnownVulnClasses())
		}
	}
}

func TestDefaultRegistry_ClassPriorityOrder(t *testing.T) {
	active := map[string]ActiveModule{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		active[m.ID()] = m
	}
	// Cheap, high-confidence techniques must claim a param before slow ones.
	chains := [][]string{
		{"sqli-error-based", "sqli-boolean-blind", "sqli-time-blind", "sqli-out-of-band"},
		{"nosqli-error-based", "nosqli-operator-injection"},
		{"command-injection-echo", "command-injection-timing", "command-injection-oast"},
		{"reflected-ssti", "ssti-detection", "ssti-blind"},
		{"ssrf-detection", "ssrf-filter-bypass", "ssrf-protocol-smuggling", "ssrf-blind"},
		{"xss-light-url-params", "xss-dom-confirm"},
	}
	for _, chain := range chains {
		for i := 1; i < len(chain); i++ {
			a, b := active[chain[i-1]], active[chain[i]]
			if a == nil || b == nil {
				t.Errorf("chain %v names an unregistered module", chain)
				break
			}
			if ModuleClassPriority(a) >= ModuleClassPriority(b) {
				t.Errorf("%s (class priority %d) must rank before %s (%d)",
					a.ID(), ModuleClassPriority(a), b.ID(), ModuleClassPriority(b))
			}
		}
	}
}

func TestOrderWithinVulnClass_DefaultsToTierRank(t *testing.T) {
	heavy := &vcTestModule{id: "heavy", class: VulnClassLFI, tags: []string{TagTierHeavy}}
	moderate := &vcTestModule{id: "moderate", class: VulnClassLFI, tags: []string{TagTierModerate}}
	plain := &vcTestModule{id: "plain"}
	mods := []ActiveModule{heavy, plain, moderate}
	OrderWithinVulnClass(mods)
	got := []string{mods[0].ID(), mods[1].ID(), mods[2].ID()}
	want := []string{"moderate", "plain", "heavy"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OrderWithinVulnClass = %v, want %v", got, want)
		}
	}
}

type vcTestModule struct {
	ActiveModule
	id    string
	class string
	tags  []string
}

func (m *vcTestModule) ID() string     { return m.id }
func (m *vcTestModule) Tags() []string { return m.tags }
func (m *vcTestModule) VulnClass() string {
	return m.class
}
