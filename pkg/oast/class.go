package oast

import "github.com/vigolium/vigolium/pkg/oast/oastclass"

// Class is the vulnerability class a callback URL was minted for. The type and
// its constants live in the leaf package oastclass so modkit can name them
// without importing this package.
type Class = oastclass.Class

// ClassFromLegacyLabel maps a free-form injection-type label to a Class using
// the historical substring rules. GenerateURL runs it once when the URL is
// minted; callback classification never inspects the label.
func ClassFromLegacyLabel(label string) Class { return oastclass.FromLegacyLabel(label) }

// class returns the context's class, deriving it from the label for a context
// built without one (tests, contexts recorded before classes existed).
func (p PayloadContext) class() Class {
	if p.Class != "" {
		return p.Class
	}
	return oastclass.FromLegacyLabel(p.InjectionType)
}
