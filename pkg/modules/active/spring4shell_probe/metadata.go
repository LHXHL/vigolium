package spring4shell_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring4shell-probe"
	ModuleName  = "Spring4Shell Probe"
	ModuleShort = "Detects Spring4Shell (CVE-2022-22965) ClassLoader data binding via a safe status differential"
)

var (
	ModuleDesc = `**What it means:** The endpoint binds request parameters onto the JVM ClassLoader through Spring data binding, the root cause of Spring4Shell (CVE-2022-22965). Confirmed by a safe status differential on the harmless DefaultAssertionStatus property: true and false bind (2xx), a non-boolean fails conversion (400), twice.

**How it's exploited:** An attacker rewrites ClassLoader properties such as Tomcat's access-log settings to drop a JSP web shell, achieving remote code execution.

**Fix:** Upgrade to Spring Framework 5.3.18+/5.2.20+ (Spring Boot 2.6.6+), or set disallowed fields on the WebDataBinder.`

	ModuleConfirmation = "Confirmed when class.module.classLoader.DefaultAssertionStatus=true and =false both return the same 2xx status while a non-boolean value returns 400, a random parameter with the same non-boolean value does not return 400, and the true/non-boolean split reproduces in a second round"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	// "spring" and "java" are known tech tags, so the executor derives the
	// TechAware allowlist from them: the probe runs only on hosts fingerprinted
	// as Spring or Java (or before any fingerprint exists).
	ModuleTags = []string{"spring", "java", "rce", "moderate"}
)
