package modkit

import "github.com/vigolium/vigolium/pkg/oast/oastclass"

// ClassedOASTProvider is implemented by OAST providers that accept the
// callback's vulnerability class explicitly (the real *oast.Service). It is
// kept separate from OASTProvider so existing providers and test fakes that
// only implement GenerateURL keep compiling.
type ClassedOASTProvider interface {
	GenerateURLFor(cls oastclass.Class, targetURL, paramName, label, moduleID, requestHash string) string
}

// OASTURLFor mints a callback URL whose callbacks are rated as class cls.
// label is the human injection-type label shown in the finding. Modules use
// this instead of OASTProvider.GenerateURL so the rating never depends on the
// label's wording. A provider without GenerateURLFor falls back to GenerateURL
// (its class is then derived from label).
func OASTURLFor(p OASTProvider, cls oastclass.Class, targetURL, paramName, label, moduleID, requestHash string) string {
	if p == nil {
		return ""
	}
	if cp, ok := p.(ClassedOASTProvider); ok {
		return cp.GenerateURLFor(cls, targetURL, paramName, label, moduleID, requestHash)
	}
	return p.GenerateURL(targetURL, paramName, label, moduleID, requestHash)
}
