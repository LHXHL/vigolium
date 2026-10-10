package http_request_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "http-request-smuggling"
	ModuleName  = "HTTP Request Smuggling"
	ModuleShort = "Detects HTTP request smuggling via CL.TE, TE.CL and CL.0 desync"
)

var (
	ModuleDesc = `**What it means:** A front-end and back-end disagree about where one HTTP request ends. Either conflicting Content-Length/Transfer-Encoding framing (CL.TE, TE.CL, TE.TE) caused a reproducible timing anomaly (inferred, suspect), or a back-end ignored a POST's Content-Length on a static path and parsed its body as the next request (CL.0, observed).

**How it's exploited:** An attacker prepends crafted bytes to a victim's request on a shared connection, hijacking requests, stealing cookies, or poisoning the cache.

**Fix:** Make the front-end and back-end agree on framing: reject requests with both Content-Length and Transfer-Encoding, make every endpoint consume the declared body, prefer HTTP/2.`

	ModuleConfirmation = "Confirmed when conflicting CL/TE headers, sent verbatim over HTTP/1.1 to a keep-alive host, cause a reproducible timing anomaly that a well-formed control POST of the same shape to the same path does not - and neither response came from an edge/CDN/WAF block or an auth gate. Timing alone cannot separate a desync from any other stalled read, so the result is a lead: proof requires showing the smuggled prefix affect a later request on the same connection. CL.0 shows exactly that: a POST to a static/redirect path whose body is a smuggled GET to a random 404 canary, followed by a GET on the SAME reused connection that comes back as the canary's 404 instead of its own response - reproduced with a fresh canary, against a baseline where the path's own answer is stable and not 404, and against a same-length benign POST whose follow-up is answered normally. A host that closes the connection is never reported"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"request-smuggling", "heavy"}
)
