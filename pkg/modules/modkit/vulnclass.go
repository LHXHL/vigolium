package modkit

// Vulnerability classes for cross-module (param, class) dedup. A module that
// returns one of these from VulnClass() shares the ParameterFindingRegistry
// slot with every other module of the same class: once any of them reports a
// finding on a parameter, the rest skip that parameter at that location.
//
// They live in modkit (not pkg/modules) so module packages can use them
// without an import cycle; pkg/modules re-exports them alongside the class
// list the registry contract test checks against. Declare a class only for
// modules that test the same sink: tech-specific probes (log4shell, struts
// OGNL, PDF generators, AEM XXE) stay unclassified.
const (
	VulnClassSQLi          = "sqli"
	VulnClassNoSQLi        = "nosqli"
	VulnClassCmdi          = "cmdi"
	VulnClassCodeInjection = "code-injection"
	VulnClassSSTI          = "ssti"
	VulnClassCSTI          = "csti"
	VulnClassSSRF          = "ssrf"
	VulnClassLFI           = "lfi"
	VulnClassXSS           = "xss"
	// VulnClassXSSStored is separate from VulnClassXSS on purpose: a stored
	// sink is a different bug on the same parameter as a reflected one.
	VulnClassXSSStored    = "xss-stored"
	VulnClassCRLF         = "crlf"
	VulnClassOpenRedirect = "open-redirect"
	VulnClassXXE          = "xxe"
	VulnClassLDAP         = "ldap"
	VulnClassXPath        = "xpath"
	VulnClassSSI          = "ssi"
	VulnClassSMTPHeader   = "smtp-header"
	VulnClassESI          = "esi"
)

// Class cost ranks for modules.ClassPrioritized: within one vuln class the
// executor dispatches cheaper, higher-confidence techniques first so they
// claim the parameter before the slow ones run. Lower runs earlier. Values
// leave room for in-between ranks (e.g. ClassCostInBand+1).
const (
	ClassCostInBand  = 10 // error-based / reflected / evaluated output
	ClassCostBoolean = 20 // boolean / differential
	ClassCostTiming  = 30 // time-delay inference
	ClassCostBrowser = 35 // headless-browser confirmation
	ClassCostOAST    = 40 // out-of-band callbacks (slowest to resolve)
)
