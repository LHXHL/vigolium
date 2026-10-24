// Package php2shell holds what the php2shell active probe and the passive
// version audit share about CVE-2026-109618 / CVE-2026-109619: the first fixed
// release of each affected PHP branch and the advisory references.
package php2shell

import (
	"regexp"
	"strconv"
)

// CVEs names both identifiers the advisory assigns to the php2shell bug.
const CVEs = "CVE-2026-109618 / CVE-2026-109619"

// References are attached to every php2shell result.
var References = []string{
	"https://calif.io/php2shell/",
	"https://github.com/assetnote/php2shell-scanner",
}

// fixedPatch maps an affected PHP major.minor branch to its first patched
// release number (8.2.35, 8.3.36, 8.4.27, 8.5.12). Branches not listed are not
// judged: an older EOL branch gets no vendor fix, and a newer one postdates the
// bug, so neither can be called fixed or vulnerable from the version alone.
var fixedPatch = map[[2]int]int{
	{8, 2}: 35,
	{8, 3}: 36,
	{8, 4}: 27,
	{8, 5}: 12,
}

// Verdict is what an advertised PHP version says about php2shell.
type Verdict int

const (
	// Unknown: no PHP version was advertised, or its branch is not in the table.
	Unknown Verdict = iota
	// Fixed: the advertised release is at or past the branch's fix.
	Fixed
	// Vulnerable: the advertised release predates the branch's fix.
	Vulnerable
)

var versionRe = regexp.MustCompile(`(?i)PHP/(\d+)\.(\d+)\.(\d+)`)

// Version extracts the "PHP/x.y.z" version from an X-Powered-By (or Server)
// header value. It returns "" when no full three-part version is present.
func Version(header string) string {
	m := versionRe.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// VerdictFor judges the PHP version advertised in header. A distribution
// backport can patch an older-numbered build, so Vulnerable is a lead to
// verify, not proof.
func VerdictFor(header string) Verdict {
	m := versionRe.FindStringSubmatch(header)
	if m == nil {
		return Unknown
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	fixed, ok := fixedPatch[[2]int{major, minor}]
	if !ok {
		return Unknown
	}
	if patch >= fixed {
		return Fixed
	}
	return Vulnerable
}

// FixedRelease returns the first patched release on the branch of the version
// advertised in header ("8.3.36"), or "" when the branch is not judged.
func FixedRelease(header string) string {
	m := versionRe.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	fixed, ok := fixedPatch[[2]int{major, minor}]
	if !ok {
		return ""
	}
	return m[1] + "." + m[2] + "." + strconv.Itoa(fixed)
}
