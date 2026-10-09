package text4shell_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "text4shell-probe"
	ModuleName  = "Text4Shell Probe"
	ModuleShort = "Detects Text4Shell (CVE-2022-42889) Commons Text interpolation via OAST dns/url lookups"
)

var (
	ModuleDesc = `**What it means:** User input reaches an Apache Commons Text StringSubstitutor with the default lookups (versions 1.5 to 1.9), so "${prefix:...}" expressions in the input are evaluated (Text4Shell, CVE-2022-42889). Confirmed by injecting dns and url lookups and seeing the server resolve or fetch the out-of-band callback host.

**How it's exploited:** An attacker sends a "${script:javascript:...}" lookup that the server evaluates, achieving remote code execution.

**Fix:** Upgrade Apache Commons Text to 1.10.0 or later, and never interpolate untrusted input with StringSubstitutor.`

	ModuleConfirmation = "Confirmed when the target resolves (DNS) or fetches (HTTP) a unique OAST callback host injected in a Commons Text ${dns:...} or ${url:UTF-8:...} lookup"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	// "java" is a known tech tag, so the executor derives the TechAware
	// allowlist from it.
	ModuleTags = []string{"java", "rce", "injection", "oast", "moderate"}
)
