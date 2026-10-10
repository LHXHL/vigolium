package smtp_header_injection

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// VulnClass enables cross-module (param, class) dedup: once any smtp-header module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassSMTPHeader }
