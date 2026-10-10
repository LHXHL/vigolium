package cli

import (
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/scanplan"
)

// schema_registry.go declares the -j document shapes `vigolium schema`
// publishes, one table like machine_kinds.go: the item type and the
// command-specific top-level keys of each registered command.
//
// Several views are built as maps (compactFindingView, compactRecordView,
// bodyView: --fields projects them, and keys appear only when set). Their
// typed mirrors below are the schema's source; schema_registry_test.go keeps
// each mirror's key set equal to the selectable --fields vocabulary and the
// emitted keys a subset of it, so a key added to a builder without its mirror
// fails a test instead of shipping undocumented.

// findingViewSchema mirrors compactFindingView (`finding -j`, the scan
// document's items, `scan diff` rows). Keys emitted only when set are
// omitempty; --fields may drop any key.
type findingViewSchema struct {
	ID                 int64                           `json:"id,omitempty"`
	FindingHash        string                          `json:"finding_hash,omitempty"`
	Severity           string                          `json:"severity"`
	Confidence         string                          `json:"confidence"`
	ModuleID           string                          `json:"module_id"`
	ModuleName         string                          `json:"module_name"`
	ModuleType         string                          `json:"module_type"`
	FindingSource      string                          `json:"finding_source"`
	RecordKind         string                          `json:"record_kind"`
	EvidenceGrade      string                          `json:"evidence_grade"`
	Short              string                          `json:"short,omitempty"`
	Description        string                          `json:"description,omitempty"`
	URL                string                          `json:"url,omitempty"`
	Hostname           string                          `json:"hostname,omitempty"`
	MatchedAt          []string                        `json:"matched_at,omitempty"`
	ExtractedResults   []string                        `json:"extracted_results,omitempty"`
	AdditionalEvidence []string                        `json:"additional_evidence,omitempty"`
	Tags               []string                        `json:"tags,omitempty"`
	CWEID              string                          `json:"cwe_id,omitempty"`
	CVSSScore          float64                         `json:"cvss_score,omitempty"`
	Remediation        string                          `json:"remediation,omitempty"`
	Status             string                          `json:"status,omitempty"`
	StatusNote         string                          `json:"status_note,omitempty"`
	StatusActor        string                          `json:"status_actor,omitempty"`
	ScanUUID           string                          `json:"scan_uuid,omitempty"`
	AgenticScanUUID    string                          `json:"agentic_scan_uuid,omitempty"`
	RepoName           string                          `json:"repo_name,omitempty"`
	SourceFile         string                          `json:"source_file,omitempty"`
	FoundAt            string                          `json:"found_at"`
	HTTPRecordUUIDs    []string                        `json:"http_record_uuids,omitempty"`
	OriginRecordUUID   string                          `json:"origin_record_uuid,omitempty"`
	InsertionPoint     *database.FindingInsertionPoint `json:"insertion_point,omitempty"`
	Payload            string                          `json:"payload,omitempty"`
	Verification       *database.FindingVerification   `json:"verification,omitempty"`
	VerifiedAt         string                          `json:"verified_at,omitempty"`
	ResponseEvidence   string                          `json:"response_evidence,omitempty"`
	Request            string                          `json:"request,omitempty"`
	Response           string                          `json:"response,omitempty"`
	Records            []recordViewSchema              `json:"records,omitempty"`
	RecordsTotal       int                             `json:"records_total,omitempty"`
	RecordsTruncated   bool                            `json:"records_truncated,omitempty"`
	RecordsError       string                          `json:"records_error,omitempty"`
}

// recordViewSchema mirrors compactRecordView (`traffic -j`, a finding's
// --with-records rows). The host facts (a, aaaa, cname, tls) are merged in at
// the top level, as database.HostFacts marshals them.
type recordViewSchema struct {
	UUID                  string `json:"uuid"`
	Method                string `json:"method"`
	URL                   string `json:"url"`
	Host                  string `json:"host"`
	StatusCode            int    `json:"status_code"`
	ResponseContentType   string `json:"response_content_type"`
	ResponseContentLength int64  `json:"response_content_length"`
	ResponseTimeMS        int64  `json:"response_time_ms"`
	ResponseWords         int64  `json:"response_words"`
	Source                string `json:"source"`
	ScanUUID              string `json:"scan_uuid,omitempty"`
	ResponseTitle         string `json:"response_title,omitempty"`
	IP                    string `json:"ip,omitempty"`
	RiskScore             int    `json:"risk_score,omitempty"`
	SurfaceScore          int    `json:"surface_score,omitempty"`
	IsAuthenticated       bool   `json:"is_authenticated,omitempty"`
	database.HostFacts
	Technology     []string                 `json:"technology,omitempty"`
	Remarks        []string                 `json:"remarks,omitempty"`
	BodyCompaction *database.BodyCompaction `json:"body_compaction,omitempty"`
	Request        *bodyViewSchema          `json:"request,omitempty"`
	Response       *bodyViewSchema          `json:"response,omitempty"`
}

// bodyViewSchema mirrors bodyView: one request or response, headers verbatim
// and the body decoded, capped and stubbed when binary.
type bodyViewSchema struct {
	RawHeaders      string `json:"raw_headers,omitempty"`
	BodySize        int64  `json:"body_size,omitempty"`
	BodySizeAtLeast int64  `json:"body_size_at_least,omitempty"`
	BodySHA256      string `json:"body_sha256,omitempty"`
	DecoderCapped   bool   `json:"decoder_capped,omitempty"`
	DecoderLimit    int64  `json:"decoder_limit,omitempty"`
	DecoderHint     string `json:"decoder_hint,omitempty"`
	BodyOmitted     string `json:"body_omitted,omitempty"`
	Body            string `json:"body,omitempty"`
	BodyTruncated   bool   `json:"body_truncated,omitempty"`
}

// scanDiffItemSchema is one `scan diff` row: the finding view plus the class.
type scanDiffItemSchema struct {
	findingViewSchema
	// Change is new, unchanged, fixed or not_reobserved.
	Change        string `json:"change"`
	FirstSeenScan string `json:"first_seen_scan,omitempty"`
}

// Extras: each command's own top-level keys. omitempty = optional.

type provenanceExtras struct {
	// ProvenanceWarning is scan_not_found or scan_uuid_not_stamped when a
	// --scan-uuid read matched nothing for a reason worth naming.
	ProvenanceWarning string `json:"provenance_warning,omitempty"`
	ProvenanceDetail  string `json:"provenance_detail,omitempty"`
}

type curlExtras struct {
	// Skipped counts rows with no stored request to render (--curl).
	Skipped int `json:"skipped,omitempty"`
	// Redacted says credentials were masked (--curl --redact-auth).
	Redacted bool `json:"redacted,omitempty"`
}

type trafficExtras struct {
	provenanceExtras
	curlExtras
}

type findingExtras struct {
	curlExtras
	// FindingsTotal is the matched finding count under --curl, where total
	// counts the rendered rows.
	FindingsTotal int64 `json:"findings_total,omitempty"`
}

type endpointsExtras struct {
	provenanceExtras
	RecordsScanned    int64 `json:"records_scanned"`
	Capped            bool  `json:"capped"`
	UnbucketedRecords int64 `json:"unbucketed_records"`
	Collapse          int   `json:"collapse,omitempty"`
}

type paramsExtras struct {
	provenanceExtras
	RecordsScanned int64 `json:"records_scanned"`
	Capped         bool  `json:"capped"`
	ValuesRedacted bool  `json:"values_redacted"`
}

// scanDocExtras are the scan document's top-level keys (scan_document.go).
type scanDocExtras struct {
	ScanUUID          string                  `json:"scan_uuid,omitempty"`
	ScanUUIDs         []string                `json:"scan_uuids"`
	Persisted         bool                    `json:"persisted"`
	Stateless         bool                    `json:"stateless"`
	Status            string                  `json:"status"`
	Completeness      string                  `json:"completeness"`
	Reasons           []string                `json:"reasons"`
	StopReason        string                  `json:"stop_reason,omitempty"`
	Targets           []scanDocTarget         `json:"targets"`
	TargetsNotScanned []string                `json:"targets_not_scanned"`
	PhaseOutcomes     []database.PhaseOutcome `json:"phase_outcomes"`
	Modules           scanDocModules          `json:"modules"`
	CountsBySeverity  map[string]int          `json:"counts_by_severity"`
	Candidates        int64                   `json:"candidates"`
	Observations      int64                   `json:"observations"`
	Errors            []scanDocError          `json:"errors"`
	ItemsTruncated    bool                    `json:"items_truncated"`
	// Plan is the scan's stored plan (scans.plan, the `schema plan` document),
	// verbatim; null when the row has none or the document spans several scans.
	Plan       *scanplan.Plan `json:"plan"`
	DurationMS int64          `json:"duration_ms"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
}

type scanDiffExtras struct {
	Base                 scanDiffSideView `json:"base"`
	Head                 scanDiffSideView `json:"head"`
	Comparable           bool             `json:"comparable"`
	ComparabilityReasons []string         `json:"comparability_reasons"`
	History              string           `json:"history"`
	Counts               map[string]int   `json:"counts"`
	IncludeDismissed     bool             `json:"include_dismissed"`
}

type findingMarkExtras struct {
	// Status is the verdict written.
	Status    string                         `json:"status"`
	Unchanged []database.FindingStatusChange `json:"unchanged"`
	NotFound  []string                       `json:"not_found"`
}

type projectUseExtras struct {
	Created         bool              `json:"created"`
	PreviousProject string            `json:"previous_project"`
	ActivatedScope  string            `json:"activated_scope"`
	ActiveFile      string            `json:"active_file"`
	Env             map[string]string `json:"env"`
}

type projectDeleteExtras struct {
	Found   bool `json:"found"`
	Aborted bool `json:"aborted,omitempty"`
}

type oastIngestExtras struct {
	// Format is the callback log format read.
	Format     string `json:"format"`
	Callbacks  int    `json:"callbacks"`
	Matched    int    `json:"matched"`
	Unmatched  int    `json:"unmatched"`
	Duplicates int    `json:"duplicates"`
}

type moduleToggleExtras struct {
	ModulesChanged int    `json:"modules_changed"`
	ConfigPath     string `json:"config_path"`
}

// registerCommandSchema registers c with its kind taken from the
// -j document's declared kind, so the two tables cannot disagree.
func registerCommandSchema(c contract.Command) {
	if c.Kind == "" {
		c.Kind = envelopeKindForDeclared(machineKinds[c.Name])
	}
	contract.RegisterCommand(c)
}

// envelopeKindForDeclared is the `kind` a command declared as k renders
// (stream commands render a read envelope under -j).
func envelopeKindForDeclared(k machineKind) string {
	switch k {
	case kindRead, kindStream:
		return contract.KindRead
	case kindMutation:
		return contract.KindMutation
	case kindScan:
		return contract.KindScan
	}
	return ""
}

func init() {
	curlVariant := []contract.Variant{{Flag: "--curl", Item: curlItem{}}}

	registerCommandSchema(contract.Command{Name: "finding", Item: findingViewSchema{}, Variants: curlVariant,
		Extras: findingExtras{}, Description: "Stored findings as finding views; --curl rows render each finding's request as a curl command."})
	registerCommandSchema(contract.Command{Name: "traffic", Item: recordViewSchema{}, Variants: curlVariant,
		Extras: trafficExtras{}, Description: "Stored HTTP records; --curl rows render each request as a curl command."})
	registerCommandSchema(contract.Command{Name: "endpoints", Item: database.EndpointView{},
		Extras: endpointsExtras{}, Description: "Endpoints (origin + path template) aggregated from stored traffic."})
	registerCommandSchema(contract.Command{Name: "params", Item: database.ParamView{},
		Extras: paramsExtras{}, Description: "Parameters by endpoint and location, aggregated from stored traffic."})
	registerCommandSchema(contract.Command{Name: "log ls", Item: logRowView{}, Extras: logLsExtras{},
		Description: "Native and agentic scan sessions with liveness (effective_status, stale, last_write_at); --reap adds reaped and status_files_removed."})
	registerCommandSchema(contract.Command{Name: "scan status", Item: scanStatusView{}, ItemsKind: contract.ItemsObject,
		Description: "One scan's live status: phase, progress, liveness, ETA and the stored plan."})
	registerCommandSchema(contract.Command{Name: "scan wait", Item: findingViewSchema{}, Extras: scanDocExtras{},
		Description: "The finished scan's scan document (the one scan -j prints, rebuilt from the stored row), printed once the scan ends."})
	registerCommandSchema(contract.Command{Name: "scan diff", Item: scanDiffItemSchema{}, Extras: scanDiffExtras{},
		Description: "Findings classified new / unchanged / fixed / not_reobserved between two scans."})
	for _, name := range []string{"scan", "run", "scan-url", "scan-request"} {
		registerCommandSchema(contract.Command{Name: name, Item: findingViewSchema{}, Extras: scanDocExtras{},
			Description: "The scan document: one document per invocation, items are finding views."})
	}

	// Mutations.
	registerCommandSchema(contract.Command{Name: "finding mark", Item: database.FindingStatusChange{},
		Extras: findingMarkExtras{}, Description: "Findings whose status changed; unchanged and not_found list the rest."})
	registerCommandSchema(contract.Command{Name: "project create", Item: projectMutationView{},
		Description: "The project created."})
	registerCommandSchema(contract.Command{Name: "project use", Item: projectMutationView{}, Extras: projectUseExtras{},
		Description: "The project activated (or created with --create)."})
	registerCommandSchema(contract.Command{Name: "project delete", Item: projectDeleteView{}, Extras: projectDeleteExtras{},
		Description: "The project deleted, with what it held."})
	registerCommandSchema(contract.Command{Name: "oast ingest", Item: oast.IngestedFinding{}, Extras: oastIngestExtras{},
		Description: "Findings saved from logged OAST callbacks; the counters say how the callbacks were attributed."})
	registerCommandSchema(contract.Command{Name: "extensions lint", Item: extLintFile{}, Extras: extLintExtras{},
		Description: "One item per linted file with its issues (severity, line, col, message, rule); summary counts them. ok is false exactly when there are errors (exit 1, lint_failed)."})
	for _, name := range []string{"module enable", "module disable"} {
		registerCommandSchema(contract.Command{Name: name, Item: moduleToggleView{}, Extras: moduleToggleExtras{},
			Description: "Every module the search matched, each saying whether this run flipped it."})
	}
}
