package php2shell_version

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php2shell-version"
	ModuleName  = "php2shell Unpatched PHP Version"
	ModuleShort = "Flags responses advertising a PHP release that predates the php2shell fix (CVE-2026-109618 / CVE-2026-109619)"
)

var (
	ModuleDesc = `**What it means:** The X-Powered-By or Server header advertises a PHP release older than the php2shell fix (8.2.35, 8.3.36, 8.4.27, 8.5.12). This is read from the version alone: a distribution backport can patch an older-numbered build, and nothing was sent to confirm it.

**How it's exploited:** On an unpatched build, crafted multipart requests with deeply nested array keys crash PHP workers and can reach remote code execution, without authentication.

**Fix:** Upgrade PHP to a fixed release or the vendor backport, and set expose_php = Off.`

	ModuleConfirmation = "Reported when an X-Powered-By or Server header names a PHP 8.2-8.5 release below that branch's php2shell fix"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"php", "cve", "outdated-component", "light"}
)
