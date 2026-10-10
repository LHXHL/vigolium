package core

import (
	goruntime "runtime"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// HookRunner transforms requests before scanning and filters results after scanning.
type HookRunner interface {
	RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error)
	RunPostHooks(result *output.ResultEvent) (*output.ResultEvent, error)
}

// OASTFlusher is implemented by the OAST service to allow the executor to flush
// pending interactions after scanning completes.
type OASTFlusher interface {
	Flush()
	Close()
}

// ExecutorConfig configures the Executor behavior.
type ExecutorConfig struct {
	Workers       int
	OnResult      func(*output.ResultEvent)
	OnCandidate   func(*output.ResultEvent)
	OnObservation func(*output.ResultEvent)
	OnTraffic     func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	// OnAuthWall is called once per item whose redirect chain the transport
	// refused to follow into a login / SSO wall (http.StoppedAtAuthWall). It
	// carries the target that bounced and the wall it bounced to.
	//
	// The executor only reports; the phase decides what to do. That split is
	// deliberate: the wall host is a scan-wide fact (it feeds the fuzz-target
	// exclusion the spidering phase already maintains) and the executor has no
	// business owning scan-wide state, while re-deriving it later from stored
	// records would mean re-parsing every 3xx in the corpus.
	OnAuthWall    func(target, wall string)
	Services      *services.Services
	HTTPRequester *http.Requester
	Repository    *database.Repository    // Optional: database storage
	RecordWriter  *database.RecordWriter  // Optional: batched record writer (preferred over Repository.SaveRecord)
	FindingWriter *database.FindingWriter // Optional: batched finding writer (preferred over Repository.SaveFinding)
	ScanUUID      string
	// ProjectUUID owns every record and finding this executor writes. An empty
	// value is silently coerced to the DEFAULT project by the repository (see
	// database.defaultProjectUUID), so a config carrying a Repository/
	// RecordWriter/FindingWriter MUST set it or its output lands in a project
	// nobody is reading. Enforced by TestExecutorConfigAlwaysSetsProjectUUID.
	ProjectUUID       string
	Hooks             HookRunner           // Optional: pre/post hooks
	ScopeMatcher      *config.ScopeMatcher // Optional: scope filtering
	ScopeOnIngest     bool                 // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher *config.ScopeMatcher // Optional: always-on static file filtering (independent of ScopeMatcher)
	FollowSubdomains  bool                 // When true, subdomain_harvest adds discovered subdomains to scope and feeds them (needs ScopeMatcher + feedback)
	SkipBaseline      bool                 // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	// RecordRedirectChain persists each followed redirect hop as its own record,
	// chained through parent_uuid, and re-pairs the final response with the
	// request that actually produced it. Off by default: it multiplies row
	// counts on every redirecting URL, and only a host-sweep style phase wants
	// the intermediate hops. See saveRedirectHops.
	RecordRedirectChain bool
	// RecordSource is the http_records.source label this executor stamps. Empty
	// means "scanner", which is what every phase used before the label became
	// configurable — so a phase that says nothing is unchanged.
	RecordSource         string
	OASTProvider         modkit.OASTProvider // Optional: OAST callback URL generator for blind vuln detection
	OASTService          OASTFlusher         // Optional: OAST service to flush after scanning
	PauseCtrl            *PauseController    // Optional: cooperative pause/resume controller
	MaxFindingsPerModule int                 // When > 0, suppress findings after this many per module
	// FindingAdmission optionally shares the per-module cap and the
	// already-admitted identity set with other executors. nil = executor-local,
	// which is right for a phase that runs exactly one Execute. The
	// dynamic-assessment phase passes ONE admission to every feedback round, so
	// the cap spans the phase and a root cause re-found in a later round does not
	// re-fire its callbacks. See FindingAdmission.
	FindingAdmission      *FindingAdmission
	MaxDuration           time.Duration                                                                                                       // When > 0, cancel execution after this duration
	FeedbackDrainTimeout  time.Duration                                                                                                       // Idle timeout for draining feedback after source EOF (default: 100ms)
	FeedbackDrainMaxStall time.Duration                                                                                                       // Hard cap on draining with workers in-flight but making no progress (0 = 2x active module timeout). Guards against a module that ignores cancellation.
	WorkerExitGrace       time.Duration                                                                                                       // Grace for worker goroutines to exit after the item channel is closed (0 = default 60s, capped at FeedbackDrainMaxStall). Kept short and separate from the drain-stall cap so shutdown stays responsive.
	IPCacheSize           int                                                                                                                 // LRU cache size for parsed insertion points (default: 4096)
	IPCache               *InsertionPointCache                                                                                                // Optional: shared IP cache (if nil, a new one is created)
	ParallelPassive       bool                                                                                                                // When true, run passive per-request modules concurrently
	PassiveModuleTimeout  time.Duration                                                                                                       // Timeout per passive module call (default: 5s). 0 uses default.
	ActiveModuleTimeout   time.Duration                                                                                                       // Timeout per active module call (default: 300s). 0 uses default. Modules may raise via TimeoutHinter.
	AdaptiveWorkers       bool                                                                                                                // When true, dynamically scale worker count based on queue depth
	MinWorkers            int                                                                                                                 // Floor for adaptive scaling (default: 2)
	MaxWorkers            int                                                                                                                 // Ceiling for adaptive scaling (default: Workers*4)
	ActiveTaskLimit       int                                                                                                                 // Max concurrent active module tasks across host/request/IP scopes
	OnStatus              func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) // Optional: periodic status callback
	StatusInterval        time.Duration                                                                                                       // Interval for OnStatus callback (default: 30s)
	// ModuleTimeouts, when non-nil, is an externally-owned counter the executor
	// increments on each active-module timeout (instead of its own private one).
	// A multi-round phase passes one shared counter so the timed-out total in the
	// status line accumulates across the per-round executors it creates.
	ModuleTimeouts *atomic.Int64
	// FirstStatusInterval, when > 0 and shorter than StatusInterval, fires the
	// very first status tick after this duration instead of waiting a full
	// StatusInterval. Useful for long-cadence status (e.g., 2m) where users
	// shouldn't have to stare at silence before the first line appears.
	FirstStatusInterval time.Duration
	// DisableFeedback drops every URL discovered by passive modules instead of
	// re-injecting it into the scan. With this flag the executor scans exactly
	// the items the input source delivers and nothing more — matching the
	// shallow per-request semantics of `vigolium scan-request`. Used by
	// scan-on-receive's default mode to avoid the cascade of new HTTP records
	// that link extractors and redirect followers would otherwise generate.
	DisableFeedback bool
	// TechFilterDisabled bypasses the tech-stack allowlist gate (see modules.TechAware).
	// Set by --no-tech-filter and automatically by --intensity=deep so deep scans
	// run every module regardless of detected stack.
	TechFilterDisabled bool
	// OnTechDetected fires once per (host, tag) when a passive fingerprint
	// module first publishes a stack detection.
	OnTechDetected func(host, tag string)
	// DeepScan mirrors --intensity=deep into ScanContext so modules can unlock
	// heavier probing (e.g. dashboard_exposure's full mount-path sweep).
	DeepScan bool
	// AllowRiskyPayloads mirrors --allow-risky-payloads (or config
	// dynamic-assessment.allow_risky_payloads) into ScanContext, unlocking
	// risk:high payloads below deep.
	AllowRiskyPayloads bool
	// ContentClassByHost seeds the per-host content-class registry from the
	// heuristics root probe (host → modkit.ContentClass string). It is the
	// fallback consulted by the content-class gate when a record's own
	// Content-Type is indeterminate. Honors the same TechFilterDisabled switch.
	ContentClassByHost map[string]string
}

// DefaultExecutorConfig returns sensible defaults.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Workers: goruntime.NumCPU(),
	}
}

// SuggestWorkerCount returns a heuristic worker count for rescans.
// It scales with the number of active modules but caps at maxWorkers.
// The floor is 2 to ensure at least minimal parallelism.
func SuggestWorkerCount(moduleCount, maxWorkers int) int {
	suggested := moduleCount * 2
	if suggested < 2 {
		suggested = 2
	}
	if suggested > maxWorkers {
		suggested = maxWorkers
	}
	return suggested
}
