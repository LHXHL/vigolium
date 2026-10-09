package jstangle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/vigolium/vigolium/internal/memlimit"
)

const (
	// minServiceMemoryBudget and maxServiceMemoryBudget bound the RAM-derived
	// default budget: an eighth of usable RAM, never below what two Bun workers
	// need and never above what five-ish workers can use.
	minServiceMemoryBudget   = int64(768 * 1024 * 1024)
	maxServiceMemoryBudget   = int64(2 * 1024 * 1024 * 1024)
	defaultServiceCacheBytes = int64(128 * 1024 * 1024)
	serviceWeightBytes       = int64(128 * 1024 * 1024)
	// serviceWorkerBytes is the budget share one Bun worker is sized against.
	serviceWorkerBytes      = int64(384 * 1024 * 1024)
	minDefaultWorkers       = 2
	maxDefaultWorkers       = 8
	defaultNormalInputBytes = int64(1 * 1024 * 1024)
	defaultMaxASTInputBytes = int64(4 * 1024 * 1024)
	// Unminifying and unpacking is a source-level pass, so it is bounded by the
	// hard input limit rather than by the AST ceiling. Equal to the default hard
	// limit; the service clamps it to whatever hard limit is configured.
	defaultMaxUnpackInputBytes = int64(16 * 1024 * 1024)
	defaultHardInputBytes      = int64(DefaultMaxInputBytes)
	// limitCodeInputOverHard counts inputs rejected for exceeding the hard input
	// limit. Discovery hands bodies up to its own 50 MiB JS ceiling to the
	// service, so without this counter the 16-50 MiB band was skipped silently.
	limitCodeInputOverHard = "js_input_over_hard_limit"
)

// Seams for tests: the default budget and worker count depend on the host.
var (
	numCPU         = runtime.NumCPU
	detectTotalRAM = func() uint64 {
		total, _ := memlimit.DetectRAM()
		return total
	}
	defaultBudgetOnce  sync.Once
	defaultBudgetBytes int64
)

// serviceMemoryBudgetFor is min(2 GiB, max(768 MiB, totalRAM/8)). Unknown RAM
// (0) yields the floor.
func serviceMemoryBudgetFor(totalRAM uint64) int64 {
	share := int64(min(totalRAM/8, uint64(maxServiceMemoryBudget)))
	return min(maxServiceMemoryBudget, max(minServiceMemoryBudget, share))
}

// defaultServiceMemoryBudget derives the default budget from usable RAM once
// per process (cgroup limits included, via internal/memlimit).
func defaultServiceMemoryBudget() int64 {
	defaultBudgetOnce.Do(func() {
		defaultBudgetBytes = serviceMemoryBudgetFor(detectTotalRAM())
	})
	return defaultBudgetBytes
}

// defaultWorkerCount is clamp(cpus/2, 2, budget/384MiB) with a hard cap of 8.
// The budget wins over the floor: under 768 MiB there is room for one worker
// only, and a second Bun process would blow the budget the user asked for.
func defaultWorkerCount(budgetBytes int64, cpus int) int {
	byBudget := int(budgetBytes / serviceWorkerBytes)
	count := max(minDefaultWorkers, min(cpus/2, maxDefaultWorkers))
	count = min(count, byBudget)
	return max(1, count)
}

var ErrServiceClosed = errors.New("jstangle service is closed")

// ServiceConfig controls process-wide admission and result reuse. Admission is
// memory-derived rather than CPU-derived because Babel AST jobs are RSS-heavy.
type ServiceConfig struct {
	MemoryBudgetBytes int64
	MaxWeight         int64
	CacheBytes        int64
	WorkerCount       int
	WorkerMaxJobs     int
	WorkerMaxRSSBytes int64
	NormalInputBytes  int64
	MaxASTInputBytes  int64
	// MaxUnpackInputBytes bounds the unminify/unpack pass, which reads source and
	// never builds an AST. Above MaxASTInputBytes and below this, a beautify-style
	// request is still dispatched instead of being answered from regex alone.
	MaxUnpackInputBytes int64
	HardInputBytes      int64
	ScannerConfig       *Config
}

func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		MemoryBudgetBytes:   defaultServiceMemoryBudget(),
		CacheBytes:          defaultServiceCacheBytes,
		NormalInputBytes:    defaultNormalInputBytes,
		MaxASTInputBytes:    defaultMaxASTInputBytes,
		MaxUnpackInputBytes: defaultMaxUnpackInputBytes,
		HardInputBytes:      defaultHardInputBytes,
		ScannerConfig:       DefaultConfig(),
	}
}

// AnalysisRequest is the single public work item accepted by the shared
// service. Content ownership remains with the caller and is never mutated.
type AnalysisRequest struct {
	Content []byte
	Options ScanOptions
}

type serviceBackend interface {
	ScanWithOptions(context.Context, []byte, ScanOptions) (*ScanResult, error)
	Capabilities() (*Capabilities, error)
}

type closeableBackend interface {
	Close() error
}

type cachedMetadata struct {
	Result     *ScanResult
	HasPayload bool
}

type cachedPayload struct {
	Code             *CodeRecord
	Beautified       *BeautifiedCode
	ArtifactContents [][]byte
}

type analysisFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  *ScanResult
	err     error
}

// Service owns weighted admission, byte-bounded caches, and cancellation-aware
// in-flight coalescing for every JSTANGLE consumer in the process.
type Service struct {
	backend serviceBackend
	// gate is the weighted admission semaphore and its capacity. Grow replaces
	// it with a larger one under growMu; a job keeps the gate it acquired from.
	gate                atomic.Pointer[admissionGate]
	growMu              sync.Mutex
	normalInputBytes    int64
	maxASTInputBytes    int64
	maxUnpackInputBytes int64
	hardInputBytes      int64

	metadataCache *byteLRU[*cachedMetadata]
	payloadCache  *byteLRU[*cachedPayload]

	flightMu sync.Mutex
	flights  map[string]*analysisFlight

	rootCtx context.Context
	cancel  context.CancelFunc
	closed  atomic.Bool
	wg      sync.WaitGroup

	cacheHits        atomic.Int64
	cacheMisses      atomic.Int64
	coalesced        atomic.Int64
	jobsStarted      atomic.Int64
	jobsCompleted    atomic.Int64
	activeWeight     atomic.Int64
	degradedJobs     atomic.Int64
	fallbackJobs     atomic.Int64
	rejectedJobs     atomic.Int64
	queueWaitNS      atomic.Int64
	metricsMu        sync.Mutex
	profileStats     map[string]ServiceProfileStats
	stageMS          map[string]float64
	recordCounts     map[string]int64
	limitHits        map[string]int64
	confidenceCounts map[string]int64
}

// ServiceProfileStats is an aggregate over actual worker/fallback jobs. Cache
// hits are reported separately and never double-count input or stage time.
type ServiceProfileStats struct {
	Jobs        int64
	Complete    int64
	Partial     int64
	Failed      int64
	InputBytes  int64
	OutputBytes int64
	DurationMS  float64
}

// ServiceStats is a race-free snapshot suitable for diagnostics/metrics.
type ServiceStats struct {
	CacheHits        int64
	CacheMisses      int64
	Coalesced        int64
	JobsStarted      int64
	JobsCompleted    int64
	ActiveWeight     int64
	MetadataEntries  int
	MetadataBytes    int64
	PayloadEntries   int
	PayloadBytes     int64
	Workers          int
	WorkerJobs       int
	WorkerRestarts   int64
	WorkerRetries    int64
	WorkerActive     int64
	WorkerStarted    int64
	DegradedJobs     int64
	FallbackJobs     int64
	RejectedJobs     int64
	QueueWait        time.Duration
	WorkerRSSBytes   int64
	Profiles         map[string]ServiceProfileStats
	StageDurationMS  map[string]float64
	RecordCounts     map[string]int64
	LimitHits        map[string]int64
	ConfidenceCounts map[string]int64
}

// resolveServiceConfig fills every defaulted field of a caller's config with
// the value the service will actually run with. Apply it exactly once to a raw
// config: CacheBytes < 0 means "disabled" and resolves to 0, which a second pass
// would read as "unset".
func resolveServiceConfig(config *ServiceConfig) ServiceConfig {
	if config == nil {
		config = DefaultServiceConfig()
	}
	resolved := *config
	if resolved.MemoryBudgetBytes <= 0 {
		resolved.MemoryBudgetBytes = defaultServiceMemoryBudget()
	}
	if resolved.MaxWeight <= 0 {
		resolved.MaxWeight = max(1, resolved.MemoryBudgetBytes/serviceWeightBytes)
	}
	if resolved.CacheBytes < 0 {
		resolved.CacheBytes = 0
	} else if resolved.CacheBytes == 0 {
		resolved.CacheBytes = defaultServiceCacheBytes
	}
	if resolved.WorkerCount <= 0 {
		resolved.WorkerCount = defaultWorkerCount(resolved.MemoryBudgetBytes, numCPU())
	}
	if resolved.WorkerMaxJobs <= 0 {
		resolved.WorkerMaxJobs = defaultWorkerMaxJobs
	}
	if resolved.WorkerMaxRSSBytes <= 0 {
		resolved.WorkerMaxRSSBytes = defaultWorkerMaxRSS
	}
	resolved.NormalInputBytes, resolved.MaxASTInputBytes, resolved.MaxUnpackInputBytes, resolved.HardInputBytes =
		resolveInputTiers(resolved.NormalInputBytes, resolved.MaxASTInputBytes, resolved.MaxUnpackInputBytes, resolved.HardInputBytes)
	if config.ScannerConfig != nil {
		scannerConfig := *config.ScannerConfig
		resolved.ScannerConfig = &scannerConfig
	}
	return resolved
}

// resolveInputTiers defaults unset tiers and enforces their ordering.
// Ordering is load-bearing: unpacking can reach the hard limit, parsing stops
// below it, and the "large profile" band sits below that.
func resolveInputTiers(normal, maxAST, maxUnpack, hard int64) (int64, int64, int64, int64) {
	if normal <= 0 {
		normal = defaultNormalInputBytes
	}
	if maxAST <= 0 {
		maxAST = defaultMaxASTInputBytes
	}
	if maxUnpack <= 0 {
		maxUnpack = defaultMaxUnpackInputBytes
	}
	if hard <= 0 {
		hard = defaultHardInputBytes
	}
	maxUnpack = min(maxUnpack, hard)
	maxAST = min(maxAST, maxUnpack)
	normal = min(normal, maxAST)
	return normal, maxAST, maxUnpack, hard
}

func NewService(config *ServiceConfig) (*Service, error) {
	resolved := resolveServiceConfig(config)
	return newServiceFromResolved(&resolved)
}

func newServiceFromResolved(resolved *ServiceConfig) (*Service, error) {
	if resolved.ScannerConfig == nil {
		resolved.ScannerConfig = DefaultConfig()
	}
	scanner, err := NewScanner(resolved.ScannerConfig)
	if err != nil {
		return nil, err
	}
	pool := newWorkerPool(scanner, workerPoolConfig{
		Count: resolved.WorkerCount, MaxJobs: resolved.WorkerMaxJobs,
		MaxRSSBytes: resolved.WorkerMaxRSSBytes,
	})
	return newServiceWithBackend(resolved, pool), nil
}

func newServiceWithBackend(config *ServiceConfig, backend serviceBackend) *Service {
	maxWeight := config.MaxWeight
	if maxWeight <= 0 {
		maxWeight = 1
	}
	cacheBytes := max(int64(0), config.CacheBytes)
	normalInputBytes, maxASTInputBytes, maxUnpackInputBytes, hardInputBytes := resolveInputTiers(
		config.NormalInputBytes, config.MaxASTInputBytes, config.MaxUnpackInputBytes, config.HardInputBytes)
	// Endpoint/flow metadata is comparatively small and more reusable; large
	// transformed/beautified documents live in an independently evictable cache.
	metadataBytes := cacheBytes / 3
	payloadBytes := cacheBytes - metadataBytes
	rootCtx, cancel := context.WithCancel(context.Background())
	service := &Service{
		backend:             backend,
		normalInputBytes:    normalInputBytes,
		maxASTInputBytes:    maxASTInputBytes,
		maxUnpackInputBytes: maxUnpackInputBytes,
		hardInputBytes:      hardInputBytes,
		metadataCache:       newByteLRU[*cachedMetadata](metadataBytes),
		payloadCache:        newByteLRU[*cachedPayload](payloadBytes),
		flights:             make(map[string]*analysisFlight),
		profileStats:        make(map[string]ServiceProfileStats),
		stageMS:             make(map[string]float64),
		recordCounts:        make(map[string]int64),
		limitHits:           make(map[string]int64),
		confidenceCounts:    make(map[string]int64),
		rootCtx:             rootCtx,
		cancel:              cancel,
	}
	service.gate.Store(&admissionGate{sem: semaphore.NewWeighted(maxWeight), max: maxWeight})
	return service
}

// admissionGate is one generation of the service's weighted admission.
type admissionGate struct {
	sem *semaphore.Weighted
	max int64
}

// workerGrower is the backend capability Grow uses to add workers.
type workerGrower interface {
	Grow(workers int) (int, error)
}

// Grow raises the service's capacity to at least workers pool workers and the
// admission weight a memoryBudgetBytes budget allows. It never lowers either:
// a value at or below the current one is a no-op, so a later caller asking for
// less cannot starve the one already relying on more. It returns the worker
// count (0 when the backend has no pool) and admission capacity now in effect.
//
// Growing admission swaps in a larger semaphore under growMu. Jobs already
// admitted keep (and release) the old one, so for as long as they run the
// service may admit up to their combined weight beyond the new capacity. That
// transient is bounded by the old capacity and ends with those jobs; the
// alternative, resizing a semaphore in place, is not something x/sync offers.
func (s *Service) Grow(workers int, memoryBudgetBytes int64) (int, int64, error) {
	if s.closed.Load() {
		return 0, 0, ErrServiceClosed
	}
	s.growMu.Lock()
	defer s.growMu.Unlock()

	current := s.gate.Load()
	maxWeight := current.max
	if wanted := memoryBudgetBytes / serviceWeightBytes; wanted > current.max {
		s.gate.Store(&admissionGate{sem: semaphore.NewWeighted(wanted), max: wanted})
		maxWeight = wanted
	}

	grower, ok := s.backend.(workerGrower)
	if !ok {
		return 0, maxWeight, nil
	}
	count, err := grower.Grow(workers)
	return count, maxWeight, err
}

var (
	defaultServiceMu sync.Mutex
	defaultService   *Service
	// defaultServiceErr is the error the first initialization returned. It is
	// sticky: every later DefaultService call answers with it.
	defaultServiceErr error
	// defaultServiceConfig is the raw config ConfigureDefaultService stored;
	// nil means DefaultServiceConfig. Resolved lazily so importing the package
	// never probes system RAM.
	defaultServiceConfig *ServiceConfig
	// activeServiceConfig is the resolved config the default service was built
	// from, valid once defaultService or defaultServiceErr is set.
	activeServiceConfig ServiceConfig
	// configMismatchWarned dedupes the mismatch warning per distinct key set.
	configMismatchWarned = map[string]bool{}
)

// ErrDefaultServiceConfigured reports a ConfigureDefaultService call that
// arrived after the shared service started with different settings. The
// running service keeps its settings; the error names the keys that differ.
var ErrDefaultServiceConfigured = errors.New("jstangle default service already running with a different configuration")

// ConfigureDefaultService sets process-wide budgets before the first caller
// resolves DefaultService. Once initialized, changing worker/cache semantics
// would split callers across incompatible brokers, so the running service is
// kept. A later call that asks for more workers or a larger memory budget grows
// it in place (Service.Grow; never shrinks). What is left is compared against
// it: an identical request is a no-op, and a different one logs one warning per
// distinct set of differing keys and
// returns ErrDefaultServiceConfigured naming them, so a `kit` or passive-module
// initialization that won the race is never silently in charge of discovery.
func ConfigureDefaultService(config *ServiceConfig) error {
	if config == nil {
		return nil
	}
	defaultServiceMu.Lock()
	defer defaultServiceMu.Unlock()
	if defaultService != nil || defaultServiceErr != nil {
		requested := resolveServiceConfig(config)
		if defaultService != nil {
			growDefaultServiceLocked(requested)
		}
		diffs := serviceConfigDiff(activeServiceConfig, requested)
		if len(diffs) == 0 {
			return nil
		}
		keys := make([]string, len(diffs))
		details := make([]string, len(diffs))
		for i, diff := range diffs {
			keys[i] = diff.Key
			details[i] = fmt.Sprintf("%s=%s (requested %s)", diff.Key, diff.Active, diff.Requested)
		}
		signature := strings.Join(keys, ",")
		if !configMismatchWarned[signature] {
			configMismatchWarned[signature] = true
			zap.L().Warn("jstangle: shared service already running; a later configuration was not applied",
				zap.Strings("keys", keys), zap.String("detail", strings.Join(details, "; ")))
		}
		return fmt.Errorf("%w: %s", ErrDefaultServiceConfigured, strings.Join(details, "; "))
	}
	copyConfig := *config
	if config.ScannerConfig != nil {
		scannerConfig := *config.ScannerConfig
		copyConfig.ScannerConfig = &scannerConfig
	}
	defaultServiceConfig = &copyConfig
	return nil
}

// growDefaultServiceLocked applies the part of a later request the running
// service can honour: more workers and a larger memory budget (admission
// weight). A request for less is left to the mismatch warning, so a discovery
// engine is never stuck with the pool a `kit` command or passive module
// happened to start first. Callers hold defaultServiceMu.
func growDefaultServiceLocked(requested ServiceConfig) {
	active := activeServiceConfig
	if requested.WorkerCount <= active.WorkerCount && requested.MemoryBudgetBytes <= active.MemoryBudgetBytes {
		return
	}
	workers, maxWeight, err := defaultService.Grow(
		max(requested.WorkerCount, active.WorkerCount),
		max(requested.MemoryBudgetBytes, active.MemoryBudgetBytes))
	if workers > active.WorkerCount {
		activeServiceConfig.WorkerCount = workers
	}
	if requested.MemoryBudgetBytes > active.MemoryBudgetBytes {
		activeServiceConfig.MemoryBudgetBytes = requested.MemoryBudgetBytes
		activeServiceConfig.MaxWeight = max(active.MaxWeight, maxWeight)
	}
	if err != nil {
		zap.L().Warn("jstangle: growing the shared service failed; it keeps running with what it has",
			zap.Int("requested_workers", requested.WorkerCount), zap.Error(err))
		return
	}
	zap.L().Debug("jstangle: grew the shared service for a later configuration",
		zap.Int("workers", activeServiceConfig.WorkerCount),
		zap.Int64("memory_budget_mb", activeServiceConfig.MemoryBudgetBytes/(1024*1024)),
		zap.Int64("max_weight", activeServiceConfig.MaxWeight))
}

// ActiveServiceConfig returns the resolved configuration of the process-wide
// service: worker count, budgets and input tiers as the service runs them,
// defaults filled in. initialized is false when the service has not started
// yet; the config is then what DefaultService would start with now.
func ActiveServiceConfig() (config ServiceConfig, initialized bool) {
	defaultServiceMu.Lock()
	defer defaultServiceMu.Unlock()
	if defaultService != nil || defaultServiceErr != nil {
		config, initialized = activeServiceConfig, true
	} else {
		config = resolveServiceConfig(defaultServiceConfig)
	}
	if config.ScannerConfig != nil {
		scannerConfig := *config.ScannerConfig
		config.ScannerConfig = &scannerConfig
	}
	return config, initialized
}

// DefaultService returns the one process-wide broker used by discovery and
// passive modules. It runs all analysis through the length-prefixed worker
// pool; Scanner is only the binary/capability helper the pool builds on.
func DefaultService() (*Service, error) {
	defaultServiceMu.Lock()
	defer defaultServiceMu.Unlock()
	if defaultService == nil && defaultServiceErr == nil {
		activeServiceConfig = resolveServiceConfig(defaultServiceConfig)
		resolved := activeServiceConfig
		defaultService, defaultServiceErr = newServiceFromResolved(&resolved)
	}
	return defaultService, defaultServiceErr
}

// serviceConfigFieldDiff is one setting that differs between the running
// service and a later request, rendered in config-file units.
type serviceConfigFieldDiff struct {
	Key       string
	Active    string
	Requested string
}

// serviceConfigDiff compares two resolved configs on the settings a caller can
// choose, keyed by their discovery.jstangle config names.
func serviceConfigDiff(active, requested ServiceConfig) []serviceConfigFieldDiff {
	mib := func(value int64) string {
		if value%(1024*1024) == 0 {
			return fmt.Sprintf("%d", value/(1024*1024))
		}
		return fmt.Sprintf("%.2f", float64(value)/(1024*1024))
	}
	var diffs []serviceConfigFieldDiff
	addInt := func(key string, a, r int) {
		if a != r {
			diffs = append(diffs, serviceConfigFieldDiff{key, fmt.Sprint(a), fmt.Sprint(r)})
		}
	}
	addMiB := func(key string, a, r int64) {
		if a != r {
			diffs = append(diffs, serviceConfigFieldDiff{key, mib(a), mib(r)})
		}
	}
	addInt("worker_count", active.WorkerCount, requested.WorkerCount)
	addMiB("memory_budget_mb", active.MemoryBudgetBytes, requested.MemoryBudgetBytes)
	addMiB("cache_mb", active.CacheBytes, requested.CacheBytes)
	addInt("worker_max_jobs", active.WorkerMaxJobs, requested.WorkerMaxJobs)
	addMiB("worker_max_rss_mb", active.WorkerMaxRSSBytes, requested.WorkerMaxRSSBytes)
	addMiB("normal_input_mb", active.NormalInputBytes, requested.NormalInputBytes)
	addMiB("max_ast_input_mb", active.MaxASTInputBytes, requested.MaxASTInputBytes)
	addMiB("max_unpack_input_mb", active.MaxUnpackInputBytes, requested.MaxUnpackInputBytes)
	addMiB("hard_input_mb", active.HardInputBytes, requested.HardInputBytes)
	return diffs
}

func (s *Service) Scan(ctx context.Context, content []byte) (*ScanResult, error) {
	return s.Analyze(ctx, AnalysisRequest{Content: content, Options: ScanOptions{Profile: ProfileLegacy}})
}

func (s *Service) ScanWithOptions(ctx context.Context, content []byte, options ScanOptions) (*ScanResult, error) {
	return s.Analyze(ctx, AnalysisRequest{Content: content, Options: options})
}

func (s *Service) Analyze(ctx context.Context, request AnalysisRequest) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	options := normalizeScanOptions(request.Options)
	hardLimit := min(s.hardInputBytes, int64(options.MaxInputBytes))
	if int64(len(request.Content)) > hardLimit {
		s.rejectedJobs.Add(1)
		s.metricsMu.Lock()
		s.limitHits[limitCodeInputOverHard]++
		s.metricsMu.Unlock()
		return nil, fmt.Errorf("%w: input=%d limit=%d", ErrInputTooLarge, len(request.Content), hardLimit)
	}
	originalProfile := options.Profile
	policy := s.inputPolicy(options.Profile, len(request.Content))
	switch policy {
	case inputPolicyLarge:
		// inputPolicy returns this band for these two profiles only.
		if options.Profile == ProfileDiscovery {
			options.Profile = ProfileDiscoveryLite
		} else {
			options.Profile = ProfileEndpoints
		}
	case inputPolicyUnpackOnly:
		// Run the one profile that needs no AST. The endpoint half of a full or
		// inspect request is served by merging a bounded string pass below.
		options.Profile = ProfileBeautify
	}
	caps, err := s.backend.Capabilities()
	if err != nil {
		return nil, err
	}
	// Capability handshake: if the embedded helper explicitly advertises its
	// profiles and the requested one is absent, fail fast with a typed error so
	// callers (js_beautify, the CSPT dom-security consumer) can skip cleanly with
	// a diagnostic instead of dispatching a job that dies with an opaque error.
	if !caps.SupportsProfile(options.Profile) {
		s.rejectedJobs.Add(1)
		return nil, fmt.Errorf("%w: %q (helper advertises %v)", ErrUnsupportedProfile, options.Profile, caps.Profiles)
	}
	key := serviceCacheKey(request.Content, options, caps.SourceHash)
	if result, ok := s.loadCache(key, options.SourceURL); ok {
		s.cacheHits.Add(1)
		return result, nil
	}
	s.cacheMisses.Add(1)

	result, err := s.doFlight(ctx, key, options.Deadline, func(jobCtx context.Context) (*ScanResult, error) {
		// Another flight may have populated the cache between the first lookup and
		// registration of this job.
		if result, ok := s.loadCache(key, options.SourceURL); ok {
			s.cacheHits.Add(1)
			return result, nil
		}

		if policy == inputPolicyFallback {
			s.jobsStarted.Add(1)
			s.fallbackJobs.Add(1)
			result := cheapFallbackAnalysis(request.Content, options, caps.SourceHash)
			s.jobsCompleted.Add(1)
			s.observeResult(options.Profile, len(request.Content), result)
			s.storeCache(key, result)
			return cloneScanResult(result)
		}

		// One gate for the whole job: a Grow swapping in a larger semaphore
		// mid-job must not make the release land on a semaphore this job never
		// acquired from.
		gate := s.gate.Load()
		weight := s.estimateWeight(gate, options.Profile, len(request.Content))
		queueStarted := time.Now()
		if err := gate.sem.Acquire(jobCtx, weight); err != nil {
			s.queueWaitNS.Add(time.Since(queueStarted).Nanoseconds())
			return nil, err
		}
		s.queueWaitNS.Add(time.Since(queueStarted).Nanoseconds())
		s.activeWeight.Add(weight)
		defer func() {
			s.activeWeight.Add(-weight)
			gate.sem.Release(weight)
		}()

		s.jobsStarted.Add(1)
		result, err := s.backend.ScanWithOptions(jobCtx, request.Content, options)
		if err == nil && !caps.Has(CapabilityTruncationCounts) {
			// A helper that counts truncation reports the cap itself. An older
			// one returns a full bucket with no reason, inferred here.
			markRequestCapReached(result, options.MaxRequests)
		}
		if err != nil {
			if jobCtx.Err() != nil || !supportsLexicalFallback(options.Profile) {
				return nil, err
			}
			result = cheapFallbackAnalysisWithReason(
				request.Content, options, caps.SourceHash, "worker_failure_fallback",
				"JavaScript worker analysis failed after its bounded retry; used string and manifest extraction",
			)
			s.fallbackJobs.Add(1)
			s.degradedJobs.Add(1)
		}
		if result == nil {
			return nil, fmt.Errorf("%w: backend returned nil result", ErrIncompleteOutput)
		}
		if analysisFailed(result) && supportsLexicalFallback(options.Profile) {
			reason := "ast_analysis_failed_fallback"
			if result.Completion != nil && result.Completion.ReasonCode != "" {
				reason = result.Completion.ReasonCode + "_fallback"
			}
			// Supplement, never replace: the non-AST stages (notably beautify) may
			// have completed on this very input, and their output is the caller's
			// primary product. See mergeFallbackInto.
			mergeFallbackInto(result, cheapFallbackAnalysisWithReason(
				request.Content, options, caps.SourceHash, reason,
				"AST analysis did not complete; used bounded string and manifest extraction",
			), reason)
			s.fallbackJobs.Add(1)
			s.degradedJobs.Add(1)
		}
		// An unpack-only dispatch produced the document but never parsed, so any
		// endpoints the caller asked for have to come from the string pass. The
		// fallback is asked under the profile the CALLER requested: options.Profile
		// was forced to beautify to reach the worker, and beautify extracts no
		// endpoints at all.
		// The band already implies the profile wants beautified output, so this
		// reduces to "not the beautify profile" - which asks for no endpoints.
		if policy == inputPolicyUnpackOnly && supportsLexicalFallback(originalProfile) {
			fallbackOptions := options
			fallbackOptions.Profile = originalProfile
			mergeFallbackInto(result, cheapFallbackAnalysisWithReason(
				request.Content, fallbackOptions, caps.SourceHash, "ast_analysis_skipped_very_large",
				fmt.Sprintf("input %d bytes exceeded the AST ceiling; unpacked without parsing and used bounded string extraction", len(request.Content)),
			), "ast_analysis_skipped_very_large")
			s.fallbackJobs.Add(1)
		}
		if originalProfile != options.Profile {
			s.degradedJobs.Add(1)
			markProfileDegraded(result, originalProfile, options.Profile, len(request.Content))
		}
		s.jobsCompleted.Add(1)
		s.observeResult(options.Profile, len(request.Content), result)
		s.storeCache(key, result)
		clone, err := cloneScanResult(result)
		if err != nil {
			return nil, err
		}
		return clone, nil
	})
	if result != nil {
		// Source URL is intentionally excluded from the content-analysis cache
		// key, so every waiter receives provenance rebound to its own asset URL.
		rebindSourceURL(result, options.SourceURL)
	}
	return result, err
}

func (s *Service) observeResult(profile AnalysisProfile, inputBytes int, result *ScanResult) {
	if result == nil {
		return
	}
	status := result.Status()
	if status == "" {
		status = "complete"
	}
	var durationMS float64
	var outputBytes int64
	var stages []StageMetric
	records := map[string]int{}
	if result.Analysis != nil {
		durationMS = result.Analysis.Stats.DurationMS
		stages = result.Analysis.Stats.StageMetrics
		for kind, count := range result.Analysis.Stats.RecordCounts {
			records[kind] = count
		}
	}
	if result.Completion != nil {
		outputBytes = result.Completion.OutputBytes
		if len(stages) == 0 {
			stages = result.Completion.StageMetrics
		}
	}
	if durationMS == 0 && result.ScanDuration > 0 {
		durationMS = float64(result.ScanDuration) / float64(time.Millisecond)
	}
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	key := string(profile)
	profileStats := s.profileStats[key]
	profileStats.Jobs++
	profileStats.InputBytes += int64(inputBytes)
	profileStats.OutputBytes += outputBytes
	profileStats.DurationMS += durationMS
	switch status {
	case "partial":
		profileStats.Partial++
	case "failed", "cancelled":
		profileStats.Failed++
	default:
		profileStats.Complete++
	}
	s.profileStats[key] = profileStats
	for _, stage := range stages {
		s.stageMS[stage.Stage] += stage.DurationMS
	}
	for kind, count := range records {
		s.recordCounts[kind] += int64(count)
	}
	addConfidence := func(kind, confidence string) {
		if confidence == "" {
			confidence = "unknown"
		}
		s.confidenceCounts[kind+"|"+confidence]++
	}
	for i := range result.RequestFacts {
		addConfidence("httpRequest", result.RequestFacts[i].Provenance.Confidence)
	}
	for i := range result.DomFlowFacts {
		addConfidence("domFlow", result.DomFlowFacts[i].Provenance.Confidence)
	}
	for i := range result.AssetFacts {
		addConfidence("assetReference", result.AssetFacts[i].Provenance.Confidence)
	}
	for i := range result.GraphQLOperations {
		addConfidence("graphqlOperation", result.GraphQLOperations[i].Provenance.Confidence)
	}
	for i := range result.WebSockets {
		addConfidence("websocket", result.WebSockets[i].Provenance.Confidence)
	}
	for i := range result.EventSources {
		addConfidence("eventSource", result.EventSources[i].Provenance.Confidence)
	}
	for i := range result.ClientRoutes {
		addConfidence("clientRoute", result.ClientRoutes[i].Provenance.Confidence)
	}
	for i := range result.BrowserFlows {
		addConfidence("browserSecurityFlow", result.BrowserFlows[i].Provenance.Confidence)
	}
	for _, diagnostic := range result.Diagnostics {
		if strings.Contains(diagnostic.Code, "limit") || strings.Contains(diagnostic.Code, "budget") ||
			strings.Contains(diagnostic.Code, "too_large") {
			s.limitHits[diagnostic.Code]++
		}
	}
}

func analysisFailed(result *ScanResult) bool {
	return result.Status() == "failed"
}

func supportsLexicalFallback(profile AnalysisProfile) bool {
	return profile != ProfileDOMSecurity && profile != ProfileBeautify
}

type serviceInputPolicy uint8

const (
	inputPolicyNormal serviceInputPolicy = iota
	inputPolicyLarge
	// inputPolicyUnpackOnly dispatches a script that is too big to parse but
	// still worth unpacking. webcrack reads source, not an AST, so the beautify
	// path costs none of the memory the AST ceiling exists to bound.
	inputPolicyUnpackOnly
	inputPolicyFallback
)

// wantsBeautifiedOutput reports whether the profile's primary product is the
// unminified/unpacked document rather than the AST-derived facts. Only these
// profiles have anything to gain from a dispatch that cannot parse.
func wantsBeautifiedOutput(profile AnalysisProfile) bool {
	return profile == ProfileBeautify || profile == ProfileFull || profile == ProfileInspect
}

// inputPolicy routes by what each ceiling actually bounds. maxASTInputBytes
// bounds Babel: above it we must not build a tree. It historically also skipped
// the engine altogether, which silently disabled unminification for exactly the
// large bundles that most need it - the caller got its input back, unchanged and
// unexplained. maxUnpackInputBytes is the real engine ceiling.
func (s *Service) inputPolicy(profile AnalysisProfile, contentBytes int) serviceInputPolicy {
	bytes := int64(contentBytes)
	if bytes > s.maxUnpackInputBytes {
		return inputPolicyFallback
	}
	if bytes > s.maxASTInputBytes {
		if wantsBeautifiedOutput(profile) {
			return inputPolicyUnpackOnly
		}
		return inputPolicyFallback
	}
	if bytes > s.normalInputBytes && (profile == ProfileDiscovery || profile == ProfileLegacy) {
		return inputPolicyLarge
	}
	return inputPolicyNormal
}

func markProfileDegraded(result *ScanResult, requested, effective AnalysisProfile, contentBytes int) {
	if result == nil {
		return
	}
	diagnostic := Diagnostic{
		Type: "diagnostic", Severity: "warning", Stage: "admission",
		Code:        "large_input_profile_degraded",
		Message:     fmt.Sprintf("input %d bytes requested profile %s; ran %s without transformed source", contentBytes, requested, effective),
		Recoverable: true,
	}
	result.Diagnostics = append(result.Diagnostics, diagnostic)
	// Enforce the downgraded contract even for alternate/test backends.
	result.Code = nil
	result.Artifacts = dropArtifactType(result.Artifacts, "transformedSource")
	if result.Analysis != nil {
		result.Analysis.Diagnostics = append(result.Analysis.Diagnostics, diagnostic)
		result.Analysis.Stats.Status = "partial"
		result.Analysis.Artifacts = dropArtifactType(result.Analysis.Artifacts, "transformedSource")
	}
	if result.Completion != nil {
		result.Completion.Status = "partial"
		result.Completion.ReasonCode = diagnostic.Code
	}
}

// requestCapDiagnosticCode is counted by observeResult's limit matcher, so a
// Go-side cap inference reaches Stats().LimitHits like a helper diagnostic.
const requestCapDiagnosticCode = "request_cap_limit"

func requestCapDiagnostic(maxRequests, dropped int) Diagnostic {
	message := fmt.Sprintf("endpoint facts reached the %d-request cap; further endpoints may have been dropped", maxRequests)
	if dropped > 0 {
		message = fmt.Sprintf("endpoint facts were limited to %d; %d more were dropped", maxRequests, dropped)
	}
	return Diagnostic{
		Type: "diagnostic", Severity: "warning", Stage: "endpoints",
		Code: requestCapDiagnosticCode, Message: message, Recoverable: true,
	}
}

// markRequestCapReached marks a result whose endpoint facts filled the request
// cap as partial with reason request_cap. Helpers that predate truncation
// counts return exactly MaxRequests facts and a "complete" status when the
// cap cut the list, so a full bucket is the only signal. A result that is
// already partial keeps its own reason; the cap is still diagnosed.
func markRequestCapReached(result *ScanResult, maxRequests int) {
	if result == nil || maxRequests <= 0 {
		return
	}
	// Older helpers already emit request_limit_reached when they drop a fact,
	// but leave the completion reason empty.
	helperReported := false
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "request_limit_reached" || diagnostic.Code == requestCapDiagnosticCode {
			helperReported = true
			break
		}
	}
	if !helperReported && len(result.RequestFacts) < maxRequests {
		return
	}
	if !helperReported {
		diagnostic := requestCapDiagnostic(maxRequests, 0)
		result.Diagnostics = append(result.Diagnostics, diagnostic)
		if result.Analysis != nil {
			result.Analysis.Diagnostics = append(result.Analysis.Diagnostics, diagnostic)
		}
	}
	if result.Analysis != nil && (result.Analysis.Stats.Status == "" || result.Analysis.Stats.Status == "complete") {
		result.Analysis.Stats.Status = "partial"
	}
	if result.Completion != nil {
		if result.Completion.Status == "" || result.Completion.Status == "complete" {
			result.Completion.Status = "partial"
		}
		if result.Completion.ReasonCode == "" && result.Completion.Status == "partial" {
			result.Completion.ReasonCode = ReasonRequestCap
		}
		result.Completion.Counts.Diagnostics = len(result.Diagnostics)
	}
}

func dropArtifactType(artifacts []ArtifactDescriptor, artifactType string) []ArtifactDescriptor {
	filtered := make([]ArtifactDescriptor, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.ArtifactType != artifactType {
			filtered = append(filtered, artifact)
		}
	}
	return filtered
}

func (s *Service) doFlight(ctx context.Context, key string, deadline time.Duration, run func(context.Context) (*ScanResult, error)) (*ScanResult, error) {
	s.flightMu.Lock()
	if existing := s.flights[key]; existing != nil {
		existing.waiters++
		s.coalesced.Add(1)
		s.flightMu.Unlock()
		return s.waitFlight(ctx, key, existing)
	}

	jobDeadline := deadline + 10*time.Second
	if jobDeadline <= 0 || jobDeadline > MaxScanTimeout {
		jobDeadline = MaxScanTimeout
	}
	jobCtx, cancel := context.WithTimeout(s.rootCtx, jobDeadline)
	flight := &analysisFlight{done: make(chan struct{}), cancel: cancel, waiters: 1}
	s.flights[key] = flight
	s.wg.Add(1)
	s.flightMu.Unlock()

	go func() {
		defer s.wg.Done()
		flight.result, flight.err = run(jobCtx)
		cancel()
		s.flightMu.Lock()
		if s.flights[key] == flight {
			delete(s.flights, key)
		}
		close(flight.done)
		s.flightMu.Unlock()
	}()

	return s.waitFlight(ctx, key, flight)
}

func (s *Service) waitFlight(ctx context.Context, key string, flight *analysisFlight) (*ScanResult, error) {
	select {
	case <-flight.done:
		if flight.err != nil {
			return nil, flight.err
		}
		return cloneScanResult(flight.result)
	case <-ctx.Done():
		s.flightMu.Lock()
		if s.flights[key] == flight {
			flight.waiters--
			if flight.waiters == 0 {
				delete(s.flights, key)
				flight.cancel()
			}
		}
		s.flightMu.Unlock()
		return nil, ctx.Err()
	}
}

// estimateWeight sizes a job against the admission gate it will acquire on,
// clamped to that gate's capacity so the job can always be admitted.
func (s *Service) estimateWeight(gate *admissionGate, profile AnalysisProfile, contentBytes int) int64 {
	bytes := int64(contentBytes)
	ceilUnits := func(unit int64) int64 {
		if bytes == 0 {
			return 0
		}
		return (bytes + unit - 1) / unit
	}
	var weight int64
	switch profile {
	case ProfileDOMSecurity:
		weight = 1 + ceilUnits(512*1024)
	case ProfileBeautify:
		weight = 4 + ceilUnits(256*1024)
	case ProfileFull, ProfileLegacy, ProfileInspect:
		weight = 5 + ceilUnits(192*1024)
	default:
		weight = 2 + ceilUnits(256*1024)
	}
	return min(max(int64(1), weight), gate.max)
}

func serviceCacheKey(content []byte, options ScanOptions, sourceHash string) string {
	digest := sha256.Sum256(content)
	keyMaterial := struct {
		ContentSHA       string
		ToolSourceHash   string
		Profile          AnalysisProfile
		Beautify         bool
		UnpackModules    bool
		MaxBundleModules int
		MaxOutputBytes   int64
		MaxArtifactBytes int64
		MaxRequests      int
		MaxASTNodes      int
		DeadlineMS       int64
		Filename         string
		MediaType        string
	}{
		ContentSHA: hex.EncodeToString(digest[:]), ToolSourceHash: sourceHash,
		Profile: options.Profile, Beautify: options.Beautify,
		UnpackModules: options.UnpackModules, MaxBundleModules: options.MaxBundleModules,
		MaxOutputBytes: options.MaxOutputBytes, MaxArtifactBytes: options.MaxArtifactBytes,
		MaxRequests: options.MaxRequests, MaxASTNodes: options.MaxASTNodes, DeadlineMS: options.Deadline.Milliseconds(),
		Filename: options.Filename, MediaType: options.MediaType,
	}
	encoded, _ := json.Marshal(keyMaterial)
	keyDigest := sha256.Sum256(encoded)
	return hex.EncodeToString(keyDigest[:])
}

func (s *Service) loadCache(key, sourceURL string) (*ScanResult, bool) {
	metadata, ok := s.metadataCache.get(key)
	if !ok || metadata == nil || metadata.Result == nil {
		return nil, false
	}
	result, err := cloneScanResult(metadata.Result)
	if err != nil {
		s.metadataCache.remove(key)
		return nil, false
	}
	if metadata.HasPayload {
		payload, payloadOK := s.payloadCache.get(key)
		if !payloadOK || payload == nil {
			return nil, false
		}
		applyCachedPayload(result, payload)
	}
	rebindSourceURL(result, sourceURL)
	return result, true
}

func (s *Service) storeCache(key string, result *ScanResult) {
	metadataResult, payload, err := splitCachedResult(result)
	if err != nil {
		return
	}
	metadata := &cachedMetadata{Result: metadataResult, HasPayload: payload != nil}
	encoded, err := json.Marshal(metadata)
	if err != nil || !s.metadataCache.add(key, metadata, int64(len(encoded))) {
		return
	}
	if payload != nil {
		if !s.payloadCache.add(key, payload, payload.size()) {
			// A metadata hit without its required payload must never be presented
			// as a complete result.
			s.metadataCache.remove(key)
		}
	}
}

func splitCachedResult(result *ScanResult) (*ScanResult, *cachedPayload, error) {
	clone, err := cloneScanResult(result)
	if err != nil {
		return nil, nil, err
	}
	payload := &cachedPayload{Code: clone.Code, Beautified: clone.Beautified}
	clone.Code = nil
	clone.Beautified = nil
	for i := range clone.Artifacts {
		if len(clone.Artifacts[i].Content) > 0 {
			payload.ArtifactContents = append(payload.ArtifactContents, append([]byte(nil), clone.Artifacts[i].Content...))
			clone.Artifacts[i].Content = nil
		} else {
			payload.ArtifactContents = append(payload.ArtifactContents, nil)
		}
	}
	if payload.Code == nil && payload.Beautified == nil {
		hasContent := false
		for _, content := range payload.ArtifactContents {
			hasContent = hasContent || len(content) > 0
		}
		if !hasContent {
			payload = nil
		}
	}
	return clone, payload, nil
}

func (p *cachedPayload) size() int64 {
	if p == nil {
		return 0
	}
	var size int64
	if p.Code != nil {
		size += int64(len(p.Code.Content) + len(p.Code.Filename))
	}
	if p.Beautified != nil {
		size += int64(len(p.Beautified.Content) + len(p.Beautified.Filename))
		for _, path := range p.Beautified.ModulePaths {
			size += int64(len(path))
		}
	}
	for _, content := range p.ArtifactContents {
		size += int64(len(content))
	}
	return max(int64(1), size)
}

func applyCachedPayload(result *ScanResult, payload *cachedPayload) {
	if payload == nil {
		return
	}
	result.Code = cloneCodeRecord(payload.Code)
	result.Beautified = cloneBeautified(payload.Beautified)
	for i := range result.Artifacts {
		if i < len(payload.ArtifactContents) {
			result.Artifacts[i].Content = append([]byte(nil), payload.ArtifactContents[i]...)
		}
	}
}

func cloneScanResult(result *ScanResult) (*ScanResult, error) {
	if result == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("clone jstangle result: %w", err)
	}
	var clone ScanResult
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return nil, fmt.Errorf("clone jstangle result: %w", err)
	}
	for i := range result.Artifacts {
		if i < len(clone.Artifacts) {
			clone.Artifacts[i].Content = append([]byte(nil), result.Artifacts[i].Content...)
		}
	}
	return &clone, nil
}

func cloneCodeRecord(record *CodeRecord) *CodeRecord {
	if record == nil {
		return nil
	}
	clone := *record
	return &clone
}

func cloneBeautified(value *BeautifiedCode) *BeautifiedCode {
	if value == nil {
		return nil
	}
	clone := *value
	clone.ModulePaths = append([]string(nil), value.ModulePaths...)
	return &clone
}

func rebindSourceURL(result *ScanResult, sourceURL string) {
	if result == nil {
		return
	}
	for i := range result.AssetFacts {
		result.AssetFacts[i].ParentSourceURL = sourceURL
	}
	if result.Analysis != nil {
		result.Analysis.Source.URL = sourceURL
		// Source URL is intentionally excluded from the content/profile cache key.
		// Asset records are the only typed records that embed their parent source,
		// so rebind their raw envelope representation as well as the decoded slice.
		for i, record := range result.Analysis.Records {
			var header struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(record, &header) != nil || header.Kind != "assetReference" {
				continue
			}
			var fact AssetReferenceFact
			if json.Unmarshal(record, &fact) != nil {
				continue
			}
			fact.ParentSourceURL = sourceURL
			if rebound, err := json.Marshal(fact); err == nil {
				result.Analysis.Records[i] = rebound
			}
		}
	}
}

func (s *Service) Capabilities() (*Capabilities, error) {
	return s.backend.Capabilities()
}

func (s *Service) EnsureReady() error {
	_, err := s.backend.Capabilities()
	return err
}

func (s *Service) Checksum() string {
	if backend, ok := s.backend.(interface{ Checksum() string }); ok {
		return backend.Checksum()
	}
	return ""
}

func (s *Service) Stats() ServiceStats {
	metadataEntries, metadataBytes := s.metadataCache.lenAndBytes()
	payloadEntries, payloadBytes := s.payloadCache.lenAndBytes()
	stats := ServiceStats{
		CacheHits: s.cacheHits.Load(), CacheMisses: s.cacheMisses.Load(),
		Coalesced: s.coalesced.Load(), JobsStarted: s.jobsStarted.Load(),
		JobsCompleted: s.jobsCompleted.Load(), ActiveWeight: s.activeWeight.Load(),
		MetadataEntries: metadataEntries, MetadataBytes: metadataBytes,
		PayloadEntries: payloadEntries, PayloadBytes: payloadBytes,
	}
	if backend, ok := s.backend.(interface{ Stats() WorkerPoolStats }); ok {
		pool := backend.Stats()
		stats.Workers = pool.Workers
		stats.WorkerJobs = pool.Jobs
		stats.WorkerRestarts = pool.Restarts
		stats.WorkerRetries = pool.Retries
		stats.WorkerActive = pool.ActiveJobs
		stats.WorkerStarted = pool.JobsStarted
		stats.WorkerRSSBytes = pool.RSSBytes
	}
	stats.DegradedJobs = s.degradedJobs.Load()
	stats.FallbackJobs = s.fallbackJobs.Load()
	stats.RejectedJobs = s.rejectedJobs.Load()
	stats.QueueWait = time.Duration(s.queueWaitNS.Load())
	s.metricsMu.Lock()
	stats.Profiles = cloneMap(s.profileStats)
	stats.StageDurationMS = cloneMap(s.stageMS)
	stats.RecordCounts = cloneMap(s.recordCounts)
	stats.LimitHits = cloneMap(s.limitHits)
	stats.ConfidenceCounts = cloneMap(s.confidenceCounts)
	s.metricsMu.Unlock()
	return stats
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	result := make(map[K]V, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (s *Service) ClearCache() {
	s.metadataCache.clear()
	s.payloadCache.clear()
}

func (s *Service) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.cancel()
	s.flightMu.Lock()
	for key, flight := range s.flights {
		delete(s.flights, key)
		flight.cancel()
	}
	s.flightMu.Unlock()
	s.wg.Wait()
	s.ClearCache()
	if backend, ok := s.backend.(closeableBackend); ok {
		return backend.Close()
	}
	return nil
}
