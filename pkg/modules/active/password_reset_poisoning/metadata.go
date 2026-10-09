package password_reset_poisoning

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "password-reset-poisoning"
	ModuleName  = "Password Reset Poisoning"
	ModuleShort = "Detects password-reset link poisoning by replaying recorded reset requests with OAST hosts in Host and forwarding headers"
)

var (
	ModuleDesc = `**What it means:** The password-reset flow builds the emailed reset link from a client-supplied host (Host, X-Forwarded-Host, X-Host or Forwarded). Confirmed when a recorded reset request, replayed with a unique out-of-band host in those headers, yields a callback from the emailed link.

**How it's exploited:** An attacker requests a reset for the victim's account with their own host injected. The victim's email links to the attacker, who captures the reset token when it is clicked or prefetched and takes over the account.

**Fix:** Build reset links from a configured canonical origin and ignore client-supplied Host and X-Forwarded-* values.`

	ModuleConfirmation = "Confirmed when a DNS or HTTP callback reaches a unique OAST host planted in the Host, X-Forwarded-Host, X-Host or Forwarded header of a replayed password-reset request"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	// "risk:high" is modules.TagRiskHigh (a literal here: pkg/modules imports
	// this package). Each replay sends a real reset email, so a broad
	// selection only runs the module at --intensity deep or with
	// --allow-risky-payloads; -m still runs it explicitly.
	ModuleTags = []string{"authentication", "host-header", "oast", "moderate", "risk:high"}
)
