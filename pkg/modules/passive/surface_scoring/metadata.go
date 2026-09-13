package surface_scoring

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "surface-scoring"
	ModuleName  = "Attack Surface Scoring"
	ModuleShort = "Deterministic per-record attack-surface score (0-100) and technology stack"
)

var (
	ModuleDesc = `**What it means:** A prioritization signal, not a vulnerability. Each record scores 0-100 as the percentage of the surface signals present, spanning input carried or advertised, method, the host's stack, legacy handlers, session and login surface, non-standard ports, response shape (rich HTML, SPA, JSON, answered), and origin posture (dynamic, permissive CORS, leaked internals, API).

**How it's exploited:** No direct exploit. The score lands in ` + "`http_records.surface_score`" + ` so an analyst or agent can rank the corpus by attackable surface, absolute and comparable across hosts and scans. The same pass writes the host's detected stack to ` + "`http_records.technology`" + `.

**Fix:** No remediation required.`

	ModuleConfirmation = "Always emitted as record metadata; the score is derived from the request and response's own properties plus the host's detected tech stack"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"behavior-analysis", "light"}
)
