package jsext

import _ "embed"

// TypeDefinitionsFileName is the file name `ext types` and `ext preset` write
// the embedded declarations to, and that extension sources reference with
// `/// <reference path="./vigolium.d.ts" />`.
const TypeDefinitionsFileName = "vigolium.d.ts"

//go:embed vigolium.d.ts
var typeDefinitions string

// TypeDefinitions returns the TypeScript declarations for the vigolium.*
// extension API, matching this binary. TestDTSMatchesRegisteredFuncs keeps the
// declared functions in sync with allFuncDefs().
func TypeDefinitions() string {
	return typeDefinitions
}
