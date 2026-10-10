// Package oastclass defines the vulnerability class an OAST callback URL is
// minted for. The class decides how a correlated callback is rated (see
// oast.classifyInteraction), so it is fixed once when the URL is minted rather
// than re-derived from a free-form label at callback time.
//
// It is a leaf package so pkg/modules/modkit (which pkg/oast depends on) can
// name the type; pkg/oast re-exports it as oast.Class.
package oastclass

import "strings"

// Class is the vulnerability class of a planted OAST payload.
type Class string

const (
	// SSRF is a URL the target fetches server-side (blind SSRF, PDF renderer,
	// image proxy, LLM tool fetch, …).
	SSRF Class = "ssrf"
	// SSRFSmuggle is a cross-protocol / CRLF smuggling URL; a DNS-only callback
	// cannot evidence the smuggle.
	SSRFSmuggle Class = "ssrf-smuggle"
	// XXE is an external DTD / entity reference resolved by an XML parser.
	XXE Class = "xxe"
	// CMDI is an injected OS command (nslookup/curl/wget …) or code-execution
	// sink that shells out.
	CMDI Class = "cmdi"
	// SQLi is an out-of-band SQL payload (LOAD_FILE, xp_dirtree, UTL_HTTP, …).
	SQLi Class = "sqli"
	// JWTKeyURL is a jku/x5u header URL the server dereferences for a key.
	JWTKeyURL Class = "jwt-key-url"
	// HostRouting is a request-line / host-routing probe; proxies commonly
	// fetch it themselves, so HTTP callbacks are informational.
	HostRouting Class = "host-routing"
	// HeaderHarvest is a URL planted in a request header (Referer,
	// X-Forwarded-For, internal headers, …) that a backend may harvest and fetch.
	HeaderHarvest Class = "header-harvest"
	// PasswordResetPoisoning is a poisoned Host / X-Forwarded-Host on a
	// recorded password-reset request; a callback means the emailed reset link
	// was built from the injected host.
	PasswordResetPoisoning Class = "password-reset-poisoning"
	// BlindXSS is a stored script/resource reference rendered later by a browser.
	BlindXSS Class = "blind-xss"
	// SSTI is a server-side template expression that reaches out.
	SSTI Class = "ssti"
	// Deserialization is a gadget chain that makes a DNS/HTTP request.
	Deserialization Class = "deserialization"
	// JNDI is a ${jndi:…} lookup (Log4Shell).
	JNDI Class = "jndi"
	// Text4Shell is an Apache Commons Text ${dns:…}/${url:…} interpolation lookup.
	Text4Shell Class = "text4shell"
	// ESI is an <esi:include> evaluated by an edge/cache ESI processor.
	ESI Class = "esi"
	// SMTP is an email-sending / SMTP header-injection probe (callback is mail).
	SMTP Class = "smtp"
	// MCPArg is a URL or command planted in an MCP tool/prompt/resource argument.
	MCPArg Class = "mcp-arg"
	// Generic is the fallback when nothing more specific is known; it is rated
	// like SSRF.
	Generic Class = "generic"
)

// all lists every class in a stable order. It is the single source for
// validation, the JS API error message and the vigolium.d.ts OASTClass union
// (kept in sync by a jsext drift test).
var all = []Class{
	SSRF, SSRFSmuggle, XXE, CMDI, SQLi, JWTKeyURL, HostRouting, HeaderHarvest,
	PasswordResetPoisoning, BlindXSS, SSTI, Deserialization, JNDI, Text4Shell, ESI, SMTP, MCPArg, Generic,
}

// All returns every known class in a stable order.
func All() []Class {
	out := make([]Class, len(all))
	copy(out, all)
	return out
}

// Names returns every known class as a string, in All order.
func Names() []string {
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = string(c)
	}
	return out
}

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	for _, k := range all {
		if c == k {
			return true
		}
	}
	return false
}

// Parse returns the class named s (case-insensitive, surrounding space
// ignored) and whether it is known.
func Parse(s string) (Class, bool) {
	c := Class(strings.ToLower(strings.TrimSpace(s)))
	if c.Valid() {
		return c, true
	}
	return "", false
}

// FromLegacyLabel derives a class from a free-form injection-type label, for
// callers that still mint through GenerateURL (JS payload(), the olium
// oast_mint tool) and for contexts built without a class. A label that is
// exactly a class name maps to that class; otherwise the historical substring
// rules apply, in their historical precedence; anything else is Generic.
// These substring rules exist only here — callback classification switches
// on the resulting Class.
func FromLegacyLabel(label string) Class {
	if c, ok := Parse(label); ok {
		return c
	}
	l := strings.ToLower(label)
	switch {
	case strings.Contains(l, "command"):
		return CMDI
	case strings.Contains(l, "xxe"):
		return XXE
	case strings.Contains(l, "sql"):
		return SQLi
	case strings.Contains(l, "jwt"):
		return JWTKeyURL
	case strings.Contains(l, "smuggle"):
		return SSRFSmuggle
	default:
		return Generic
	}
}
