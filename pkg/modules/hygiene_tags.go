package modules

import "strings"

// TagHygiene marks a module as a hardening advisory: it reports a missing or
// weak best-practice control (a security header, a cookie attribute, a TLS
// protocol/cipher policy) rather than an exploitable condition. Such a module
// fires on nearly every response of nearly every host, so on a crawl of any size
// it buries the exploitable findings under a wall of Info/Low rows that the
// operator already knows the answer to.
//
// The tag is orthogonal to the tier tags in tier_tags.go: a tier says how
// expensive/aggressive a module is, this says how noisy its output is. A
// hygiene module is typically "light" — cheap to run, tedious to read.
//
// The native scan runner gates these off below --intensity deep (see
// internal/runner hygieneModulesEnabled). They remain selectable at any
// intensity via --module-tag hygiene or --module-id <id>, and can be restored
// globally with `dynamic-assessment.hygiene_modules: true`.
const TagHygiene = "hygiene"

// IsHygieneModule reports whether a module's tags declare TagHygiene.
func IsHygieneModule(tags []string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), TagHygiene) {
			return true
		}
	}
	return false
}
