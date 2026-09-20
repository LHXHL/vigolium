package sourcemap_ingest

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "sourcemap-ingest"
	ModuleName  = "Source Map Ingest"
	ModuleShort = "Recovers original source from exposed source maps and ingests its routes for scanning"

	ModuleDesc = `**What it means:** A JS or CSS bundle's source map is readable anonymously, embedding the original pre-build source and internal file layout. It is found from the ` + "`sourceMappingURL`" + `, a SourceMap header, or the conventional ` + "`<bundle>.map`" + ` path.

**How it's exploited:** An attacker reads real source instead of minified output, recovering identifier names, unreferenced admin routes and hardcoded credentials that minification would obscure. Recovered routes are fed back into the scan.

**Fix:** Do not deploy ` + "`.map`" + ` files to production. Upload them to the error tracker at build time and delete them from the web root. Stripping the comment leaves it served.`

	ModuleConfirmation = "The source map was fetched anonymously and parsed as a valid version-3 document. " +
		"Recovered routes have been ingested into the scanning pipeline."
)

var (
	ModuleSeverity   = severity.Medium
	ModuleConfidence = severity.Certain
	ModuleTags       = []string{"sourcemap", "information-disclosure", "javascript", "discovery", "spec-ingest", "light"}
)
