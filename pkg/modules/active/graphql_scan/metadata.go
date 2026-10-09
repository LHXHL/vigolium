package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A confirmed GraphQL endpoint exposes security-relevant behavior. Introspection and consoles are observations; batching, depth, predictable same-principal lookup, SQL-error differences, and reflection are candidates. A finding requires demonstrated impact, such as altered query logic or cross-site (CSRF) execution.

**How it's exploited:** Attackers enumerate the schema, stress query execution, probe object access, inject resolver inputs, turn reflected errors into markup, or forge operations via GET or form POSTs.

**Fix:** Restrict introspection and consoles, parameterize resolvers, limit batching and complexity, authorize every object, encode errors, and accept only JSON POSTs.`

	ModuleConfirmation = "A live endpoint requires an exact, reproduced data.__typename response; each check is then classified as observation, candidate, or finding according to whether exploit impact is directly demonstrated"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "idor", "bola", "xss", "dos", "batching", "console", "csrf", "moderate"}
)
