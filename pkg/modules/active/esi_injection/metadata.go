package esi_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "esi-injection"
	ModuleName  = "Edge Side Includes (ESI) Injection"
	ModuleShort = "Detects Edge Side Includes injection via an in-band ESI tag oracle and an out-of-band include"
)

var (
	ModuleDesc = `**What it means:** User input is reflected into a response that a cache or CDN parses for Edge Side Includes (ESI), and is processed as markup rather than data. The scanner placed an ESI comment element between two unguessable tags and the edge removed it, while a non-ESI control tag passed through untouched.

**How it's exploited:** An attacker injects esi:include to make the edge fetch internal URLs (SSRF), pull in attacker content (XSS), or leak HttpOnly cookies through ESI variables.

**Fix:** Encode user input before reflecting it, and enable ESI processing only on trusted responses.`

	ModuleConfirmation = "Confirmed when an esi:comment element injected between two fresh unguessable tags is removed so the tags become adjacent, on a response the application rendered, while a control tag in a non-ESI namespace is not removed; or when an injected esi:include triggers an out-of-band fetch"
	// Medium, matching ssi-injection: the in-band oracle proves the edge PARSES
	// injected ESI, not that esi:include reaches anything. The out-of-band
	// include leg, when it fires, carries its own severity from the OAST service.
	ModuleSeverity   = severity.Medium
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"injection", "esi", "ssrf", "moderate"}
)
