package ssti_blind

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// VulnClass enables cross-module (param, class) dedup: once any ssti module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassSSTI }

// ClassPriority orders this module within its vuln class (lower runs first).
func (m *Module) ClassPriority() int { return modkit.ClassCostOAST }
