package sqli_out_of_band

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// ClassPriority orders this module within its vuln class (lower runs first).
func (m *Module) ClassPriority() int { return modkit.ClassCostOAST }
