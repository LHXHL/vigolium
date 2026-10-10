package modules

import (
	"context"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// ActiveModule is the interface for active scanning modules.
// Active modules send HTTP requests to detect vulnerabilities.
//
// Implementations must be thread-safe as scan methods will be called
// concurrently from multiple scanner goroutines.
type ActiveModule interface {
	Module

	// AllowedInsertionPointTypes returns which insertion point types this module supports.
	// Return AllInsertionPointTypes to accept all types.
	AllowedInsertionPointTypes() InsertionPointTypeSet

	// ScanPerInsertionPoint performs scanning for a specific insertion point.
	ScanPerInsertionPoint(
		ctx *httpmsg.HttpRequestResponse,
		ip httpmsg.InsertionPoint,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	// ScanPerRequest performs scanning once per unique request.
	ScanPerRequest(
		ctx *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	// ScanPerHost performs scanning once per unique host.
	ScanPerHost(
		ctx *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)
}

// ContextualActiveModule is an optional interface for active modules that support
// cancellation and timeout propagation through context. The executor prefers these
// methods when a module implements them, passing the per-call timeout/cancellation
// context so the module can thread it into cancellable HTTP requests
// (http.Requester.ExecuteContext). Modules can adopt this incrementally without
// breaking the legacy ActiveModule interface.
type ContextualActiveModule interface {
	ScanPerInsertionPointContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
		ip httpmsg.InsertionPoint,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	ScanPerRequestContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)

	ScanPerHostContext(
		ctx context.Context,
		item *httpmsg.HttpRequestResponse,
		httpClient *http.Requester,
		scanCtx *ScanContext,
	) ([]*output.ResultEvent, error)
}

// Prioritized is an optional interface for modules that declare execution priority.
// Lower values indicate higher priority (0 = highest). Modules without this
// interface default to DefaultModulePriority (100).
// Higher priority modules are spawned first, getting earlier access to rate-limit slots.
type Prioritized interface {
	Priority() int
}

// VulnClassifier is an optional interface for modules that declare their
// vulnerability class for cross-module deduplication. When a module reports
// a finding, the executor marks the (URL, param, vuln_class) as found.
// Other modules with the same vuln class can check and skip redundant scanning.
type VulnClassifier interface {
	VulnClass() string // e.g., "xss", "sqli", "ssti"
}

// BodyDifferentialConfirmable is an optional interface for active modules whose
// findings should be re-confirmed by the executor's safety net before being
// reported. When a module implementing it returns true, the executor replays the
// finding's payload-applied request and compares it against a clean (no-payload)
// baseline (the pre-scan baseline already on the item, plus one fresh fetch),
// requiring a reproducible, payload-driven in-band difference and rejecting
// status flips and dynamic-noise diffs (via modkit.ConfirmBodyDifferential).
//
// Only modules whose true-positive signal IS an in-band body/header difference
// should opt in. Modules whose signal is out-of-band (OAST), timing-based, a
// small error string, or whose payload mutates server state (and so must not be
// replayed) must NOT implement this — they keep their own confirmation.
type BodyDifferentialConfirmable interface {
	ConfirmsByBodyDifferential() bool
}

// ResultDifferentialConfirmable is the per-result form of
// BodyDifferentialConfirmable, for modules that mix an in-band leg with OAST or
// timing legs. The executor consults it only when the module-level interface
// is absent or returns false, and re-confirms the result by body differential
// only when it returns true. Implementations return true for in-band results
// (typically result.Signal() == output.SignalInband) and false for results
// whose proof is a callback or a delay, which a replay cannot show.
type ResultDifferentialConfirmable interface {
	ConfirmsResultByBodyDifferential(result *output.ResultEvent) bool
}

// ConfirmsByBodyDifferential reports whether m's result should go through the
// executor's body-differential re-confirmation: the module-level opt-in first,
// then the per-result one.
func ConfirmsByBodyDifferential(m Module, result *output.ResultEvent) bool {
	if c, ok := m.(BodyDifferentialConfirmable); ok && c.ConfirmsByBodyDifferential() {
		return true
	}
	if c, ok := m.(ResultDifferentialConfirmable); ok && result != nil {
		return c.ConfirmsResultByBodyDifferential(result)
	}
	return false
}

// TechAware is an optional interface for modules that only make sense against
// certain technology stacks. Implement it on framework-specific modules
// (e.g. Spring, Rails, Django) to skip them on incompatible targets.
//
// Semantics (allowlist):
//   - Return an empty slice (or do not implement) → module always runs.
//   - Return ["spring", "java"] → module runs only if the request's host has
//     at least one of those tech tags detected by the *_fingerprint passive
//     modules earlier in the same scan.
//   - If no tech has been detected for the host yet, the executor fails open
//     and runs the module anyway, so first-request scans aren't pruned.
//
// Tech tags are lowercase strings that match the tag used by fingerprint
// modules (e.g. "spring", "rails", "django", "laravel", "express", "nextjs",
// "aspnet", "php", "wordpress").
type TechAware interface {
	RequiredTechs() []string
}

// PerScanModule is an optional interface for active modules that carry mutable
// state meaningful only within ONE scan (per-host dedup maps, per-scan budgets,
// compare clients, discovery maps). The registry stores a single shared singleton
// of each module, so without isolation that state bleeds across concurrent
// server-mode scans. The runner replaces such a module with a fresh instance for
// each scan (see freshenPerScanModules); modules whose per-scan state is already
// isolated via dedup.Lazy(scanCtx.DedupMgr()) or ScanContext need not implement it.
//
// Fresh returns a new instance with zeroed per-scan state. It is typed `any`
// rather than ActiveModule so a module package can implement it without importing
// pkg/modules — which would form an import cycle with the registry; the runner
// asserts the result back to ActiveModule. Implementations are one line:
//
//	func (m *Module) Fresh() any { return New() }
type PerScanModule interface {
	Fresh() any
}
