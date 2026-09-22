package ssi_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssi-injection"
	ModuleName  = "Server-Side Includes (SSI) Injection"
	ModuleShort = "Detects Server-Side Includes injection via a bracketed server-value echo and out-of-band exec"
)

var (
	ModuleDesc = `**What it means:** User input reaches a page the web server parses for Server-Side Includes (SSI) and is evaluated as a directive rather than data. The scanner injected an echo directive between two unguessable tags; they came back around a value the server owns, which only a parser produces — evaluation, not reflection.

**How it's exploited:** An attacker injects directives to disclose server variables, read files, or run OS commands via the exec directive, which can lead to remote code execution.

**Fix:** Do not render untrusted input into SSI-parsed pages, disable the exec directive, and HTML-encode user data.`

	ModuleConfirmation = "Confirmed when an SSI echo directive injected between two fresh unguessable tags returns those tags separated by a short server-rendered value, on a response the application itself rendered, and a control round proves the target parses comments rather than stripping them; or when an SSI exec directive triggers an out-of-band interaction"
	// Medium, not High, because the in-band oracle this module reports on proves
	// DIRECTIVE EVALUATION — the server parsed an SSI comment and rendered a built-in
	// variable — and nothing more. The file read and RCE this class is named for need
	// `#include`/`#exec`, which this oracle does not exercise; a proven parse often
	// does carry `#include virtual` (Apache disables only `#exec` under
	// IncludesNOEXEC), so this rates an unexercised primitive, not an absent one. The
	// route that does prove command execution is the out-of-band `#exec` probe, and an
	// OAST callback carries its own severity rather than this default. Rating the
	// in-band echo High put an unexploited parser quirk in the same band as a
	// demonstrated compromise and pulled triage time toward it.
	ModuleSeverity   = severity.Medium
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"injection", "ssi", "rce", "heavy"}
)
