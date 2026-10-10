package modules

import (
	"maps"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// injectionFamilyClasses pins the vuln class of every module in the
// injection families that share a parameter-level sink. Modules of one class
// dedup each other per (location, param); keep tech-specific probes
// (log4shell-probe, struts-ognl-injection, pdf-generation-injection,
// aem-xxe) out of the generic classes.
var injectionFamilyClasses = map[string]string{
	"sqli-error-based":           modkit.VulnClassSQLi,
	"sqli-boolean-blind":         modkit.VulnClassSQLi,
	"sqli-time-blind":            modkit.VulnClassSQLi,
	"sqli-out-of-band":           modkit.VulnClassSQLi,
	"nosqli-error-based":         modkit.VulnClassNoSQLi,
	"nosqli-operator-injection":  modkit.VulnClassNoSQLi,
	"command-injection-echo":     modkit.VulnClassCmdi,
	"command-injection-timing":   modkit.VulnClassCmdi,
	"command-injection-oast":     modkit.VulnClassCmdi,
	"code-exec":                  modkit.VulnClassCodeInjection,
	"server-side-js-injection":   modkit.VulnClassCodeInjection,
	"reflected-ssti":             modkit.VulnClassSSTI,
	"ssti-detection":             modkit.VulnClassSSTI,
	"ssti-blind":                 modkit.VulnClassSSTI,
	"angular-template-injection": modkit.VulnClassCSTI,
	"csti-detection":             modkit.VulnClassCSTI,
	"ssrf-detection":             modkit.VulnClassSSRF,
	"ssrf-filter-bypass":         modkit.VulnClassSSRF,
	"ssrf-protocol-smuggling":    modkit.VulnClassSSRF,
	"ssrf-blind":                 modkit.VulnClassSSRF,
	"lfi-generic":                modkit.VulnClassLFI,
	"lfi-path-traversal":         modkit.VulnClassLFI,
	"xss-light-url-params":       modkit.VulnClassXSS,
	"xss-light-path":             modkit.VulnClassXSS,
	"xss-light-param-discovery":  modkit.VulnClassXSS,
	"xss-light-encoded":          modkit.VulnClassXSS,
	"xss-dom-confirm":            modkit.VulnClassXSS,
	"xss-stored":                 modkit.VulnClassXSSStored,
	"crlf-injection":             modkit.VulnClassCRLF,
	"response-header-injection":  modkit.VulnClassCRLF,
	"open-redirect":              modkit.VulnClassOpenRedirect,
	"open-redirect-confusion":    modkit.VulnClassOpenRedirect,
	"xxe-generic":                modkit.VulnClassXXE,
	"ldap-injection":             modkit.VulnClassLDAP,
	"xpath-injection":            modkit.VulnClassXPath,
	"ssi-injection":              modkit.VulnClassSSI,
	"smtp-header-injection":      modkit.VulnClassSMTPHeader,
	"esi-injection":              modkit.VulnClassESI,
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

// knownVulnClasses is the closed set a VulnClass() return value must belong
// to: the modkit.VulnClass* constants.
var knownVulnClasses = map[string]struct{}{
	modkit.VulnClassSQLi: {}, modkit.VulnClassNoSQLi: {}, modkit.VulnClassCmdi: {},
	modkit.VulnClassCodeInjection: {}, modkit.VulnClassSSTI: {}, modkit.VulnClassCSTI: {},
	modkit.VulnClassSSRF: {}, modkit.VulnClassLFI: {}, modkit.VulnClassXSS: {},
	modkit.VulnClassXSSStored: {}, modkit.VulnClassCRLF: {}, modkit.VulnClassOpenRedirect: {},
	modkit.VulnClassXXE: {}, modkit.VulnClassLDAP: {}, modkit.VulnClassXPath: {},
	modkit.VulnClassSSI: {}, modkit.VulnClassSMTPHeader: {}, modkit.VulnClassESI: {},
}

func isKnownVulnClass(c string) bool {
	_, ok := knownVulnClasses[c]
	return ok
}

func TestDefaultRegistry_VulnClassIsKnownConstant(t *testing.T) {
	for _, m := range DefaultRegistry.GetActiveModules() {
		vc, ok := m.(VulnClassifier)
		if !ok {
			continue
		}
		if c := vc.VulnClass(); !isKnownVulnClass(c) {
			t.Errorf("module %q VulnClass() = %q, not one of %v (add a modkit.VulnClass* constant)",
				m.ID(), c, slices.Sorted(maps.Keys(knownVulnClasses)))
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
	heavy := &vcTestModule{id: "heavy", class: modkit.VulnClassLFI, tags: []string{TagTierHeavy}}
	moderate := &vcTestModule{id: "moderate", class: modkit.VulnClassLFI, tags: []string{TagTierModerate}}
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
