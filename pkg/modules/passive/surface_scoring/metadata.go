package surface_scoring

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "surface-scoring"
	ModuleName  = "Attack Surface Scoring"
	ModuleShort = "Deterministic per-record attack-surface score (0-100)"
)

var (
	ModuleDesc = `**What it means:** A prioritization signal, not a vulnerability. Each record scores 0-100, 10 points per signal across ten: the request carries input, changes state, or uploads; the host has a tech stack, the path is a legacy handler (.php/.jsp/.do), or a session is carried; the response is rich HTML, an SPA shell, or JSON, and the app answered.

**How it's exploited:** No direct exploit. The score lands in ` + "`http_records.surface_score`" + ` so an analyst or agent can rank the corpus by attackable surface. Unlike the anomaly percentile it is absolute and comparable across hosts and scans.

**Fix:** No remediation required.`

	ModuleConfirmation = "Always emitted as record metadata; the score is derived from the response's own properties plus the host's detected tech stack"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"behavior-analysis", "light"}
)
