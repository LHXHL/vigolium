package jstangle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeServiceBackend struct {
	calls atomic.Int64
	scan  func(context.Context, []byte, ScanOptions) (*ScanResult, error)
}

func (b *fakeServiceBackend) ScanWithOptions(ctx context.Context, content []byte, options ScanOptions) (*ScanResult, error) {
	b.calls.Add(1)
	if b.scan != nil {
		return b.scan(ctx, content, options)
	}
	result := &ScanResult{
		Requests: []ExtractedRequest{{URL: "/api/original", Method: "GET"}},
		Code:     &CodeRecord{Filename: "asset.js", Content: "generated"},
		Analysis: &AnalysisResultV2{SchemaVersion: 2},
	}
	result.Analysis.Source.URL = options.SourceURL
	return result, nil
}

func (b *fakeServiceBackend) Capabilities() (*Capabilities, error) {
	return &Capabilities{Type: "capabilities", ProtocolVersion: ProtocolVersion, SourceHash: "test-source-hash"}, nil
}

func testService(backend serviceBackend, maxWeight, cacheBytes int64) *Service {
	return newServiceWithBackend(&ServiceConfig{MaxWeight: maxWeight, CacheBytes: cacheBytes}, backend)
}

func TestServiceCachesByContentAndRebindsSource(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := testService(backend, 4, 1024*1024)
	defer func() { _ = service.Close() }()

	content := []byte(`fetch('/api/original')`)
	first, err := service.ScanWithOptions(context.Background(), content, ScanOptions{
		Profile: ProfileDiscovery, SourceURL: "https://one.example/assets/app.js",
	})
	if err != nil {
		t.Fatalf("first analysis: %v", err)
	}
	first.Requests[0].URL = "/consumer-mutated"
	first.Code.Content = "consumer-mutated"

	second, err := service.ScanWithOptions(context.Background(), content, ScanOptions{
		Profile: ProfileDiscovery, SourceURL: "https://two.example/static/app.js",
	})
	if err != nil {
		t.Fatalf("cached analysis: %v", err)
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
	if second.Analysis == nil || second.Analysis.Source.URL != "https://two.example/static/app.js" {
		t.Fatalf("source URL was not rebound: %#v", second.Analysis)
	}
	if second.Requests[0].URL != "/api/original" || second.Code == nil || second.Code.Content != "generated" {
		t.Fatalf("cached result was mutated by another consumer: %#v", second)
	}
	stats := service.Stats()
	if stats.CacheHits != 1 || stats.JobsStarted != 1 || stats.PayloadEntries != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if profile := stats.Profiles[string(ProfileDiscovery)]; profile.Jobs != 1 || profile.Complete != 1 {
		t.Fatalf("profile metrics counted cache hits or lost the worker job: %+v", stats.Profiles)
	}
}

func TestServiceCoalescesInflightAndIsolatesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeServiceBackend{scan: func(ctx context.Context, _ []byte, _ ScanOptions) (*ScanResult, error) {
		close(started)
		select {
		case <-release:
			return &ScanResult{Requests: []ExtractedRequest{{URL: "/api/shared", Method: "GET"}}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	service := testService(backend, 4, 0)
	defer func() { _ = service.Close() }()

	ctx1, cancel1 := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := service.ScanWithOptions(ctx1, []byte("same-content"), ScanOptions{Profile: ProfileEndpoints})
		firstErr <- err
	}()
	<-started

	secondResult := make(chan *ScanResult, 1)
	secondErr := make(chan error, 1)
	go func() {
		result, err := service.ScanWithOptions(context.Background(), []byte("same-content"), ScanOptions{Profile: ProfileEndpoints})
		secondResult <- result
		secondErr <- err
	}()

	deadline := time.Now().Add(time.Second)
	for service.Stats().Coalesced == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel1()
	if err := <-firstErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("first caller error = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-secondErr; err != nil {
		t.Fatalf("second caller failed after first cancelled: %v", err)
	}
	if result := <-secondResult; result == nil || len(result.Requests) != 1 {
		t.Fatalf("second caller received incomplete result: %#v", result)
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("backend calls = %d, want 1", got)
	}
}

func TestServiceCancelsBackendWhenLastWaiterLeaves(t *testing.T) {
	started := make(chan struct{})
	backendCancelled := make(chan struct{})
	backend := &fakeServiceBackend{scan: func(ctx context.Context, _ []byte, _ ScanOptions) (*ScanResult, error) {
		close(started)
		<-ctx.Done()
		close(backendCancelled)
		return nil, ctx.Err()
	}}
	service := testService(backend, 2, 0)
	defer func() { _ = service.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.ScanWithOptions(ctx, []byte("cancel-me"), ScanOptions{Profile: ProfileEndpoints})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller error = %v, want context.Canceled", err)
	}
	select {
	case <-backendCancelled:
	case <-time.After(time.Second):
		t.Fatal("backend context was not cancelled after the last waiter left")
	}
}

func TestServiceWeightedAdmissionSerializesHeavyJobs(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{}, 2)
	var active atomic.Int64
	var maxActive atomic.Int64
	backend := &fakeServiceBackend{scan: func(ctx context.Context, content []byte, _ ScanOptions) (*ScanResult, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maxActive.Load()
			if current <= observed || maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- string(content)
		select {
		case <-release:
			return &ScanResult{Requests: []ExtractedRequest{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	service := testService(backend, 2, 0)
	defer func() { _ = service.Close() }()

	var wg sync.WaitGroup
	for _, content := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = service.ScanWithOptions(context.Background(), []byte(content), ScanOptions{Profile: ProfileEndpoints})
		}()
	}

	<-started
	select {
	case second := <-started:
		t.Fatalf("second heavy job started before admission released: %s", second)
	case <-time.After(75 * time.Millisecond):
	}
	release <- struct{}{}
	<-started
	release <- struct{}{}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent backend jobs = %d, want 1", got)
	}
}

func TestByteLRUEvictsLeastRecentlyUsedByBytes(t *testing.T) {
	cache := newByteLRU[string](6)
	cache.add("a", "A", 3)
	cache.add("b", "B", 3)
	if _, ok := cache.get("a"); !ok {
		t.Fatal("expected a in cache")
	}
	cache.add("c", "C", 3)
	if _, ok := cache.get("b"); ok {
		t.Fatal("least-recently-used entry b was not evicted")
	}
	if _, ok := cache.get("a"); !ok {
		t.Fatal("recent entry a was evicted")
	}
}

func TestServiceLargeDiscoveryUsesLiteProfile(t *testing.T) {
	var observedProfile AnalysisProfile
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		observedProfile = options.Profile
		return &ScanResult{Code: &CodeRecord{Content: "must-be-dropped"}, Analysis: &AnalysisResultV2{}}, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 128, HardInputBytes: 256,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte("fetch('/api/users') plus padding"), ScanOptions{Profile: ProfileDiscovery})
	if err != nil {
		t.Fatal(err)
	}
	if observedProfile != ProfileDiscoveryLite {
		t.Fatalf("backend profile = %q, want discovery-lite", observedProfile)
	}
	if result.Code != nil || result.Analysis == nil || result.Analysis.Stats.Status != "partial" {
		t.Fatalf("large-input degradation was not explicit: %#v", result)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "large_input_profile_degraded" {
		t.Fatalf("missing degradation diagnostic: %#v", result.Diagnostics)
	}
	if stats := service.Stats(); stats.DegradedJobs != 1 || stats.FallbackJobs != 0 {
		t.Fatalf("unexpected degradation metrics: %+v", stats)
	}
}

func TestServiceVeryLargeUsesBoundedFallbackWithoutBackend(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 64, HardInputBytes: 512,
	}, backend)
	defer func() { _ = service.Close() }()
	content := []byte("fetch('/api/users'); import('./lazy.js'); //# sourceMappingURL=app.js.map\n" + string(make([]byte, 80)))
	result, err := service.ScanWithOptions(context.Background(), content, ScanOptions{Profile: ProfileDiscovery, SourceURL: "https://example.test/assets/app.js"})
	if err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("AST backend was called %d time(s)", backend.calls.Load())
	}
	if result.Analysis == nil || result.Analysis.Stats.Status != "partial" || result.Completion == nil || result.Completion.Status != "partial" {
		t.Fatalf("fallback did not report partial output: %#v", result)
	}
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].Provenance.Confidence != "low" {
		t.Fatalf("fallback endpoint hint missing or replayable: %#v", result.RequestFacts)
	}
	if len(result.AssetFacts) < 2 {
		t.Fatalf("fallback asset extraction incomplete: %#v", result.AssetFacts)
	}
	if stats := service.Stats(); stats.FallbackJobs != 1 || stats.JobsCompleted != 1 {
		t.Fatalf("unexpected fallback metrics: %+v", stats)
	}
}

// Unminifying reads source and never builds a tree, so the AST ceiling must not
// gate it. It used to: a bundle above max_ast_input_mb was handed straight to
// the regex pass, which produces no document at all, and the caller got its own
// input back labelled "neither minified nor bundled".
func TestServiceAboveASTCeilingStillUnpacks(t *testing.T) {
	var dispatched ScanOptions
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		dispatched = options
		return &ScanResult{
			Beautified: &BeautifiedCode{Format: "webpack", ModuleCount: 400, Changed: true, Content: "// beautified"},
			Analysis:   &AnalysisResultV2{SchemaVersion: 2},
			Completion: &ScanCompletion{Status: "complete", Profile: options.Profile},
		}, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 64, MaxUnpackInputBytes: 4096, HardInputBytes: 8192,
	}, backend)
	defer func() { _ = service.Close() }()

	content := []byte(`fetch("/api/v3/late");` + strings.Repeat(" ", 200))
	result, err := service.ScanWithOptions(context.Background(), content, ScanOptions{Profile: ProfileFull})
	if err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("an unpackable input above the AST ceiling must still reach the engine; calls=%d", backend.calls.Load())
	}
	if dispatched.Profile != ProfileBeautify {
		t.Fatalf("dispatched profile = %q, want beautify (the one profile that needs no AST)", dispatched.Profile)
	}
	if !result.HasBeautified() || result.Beautified.ModuleCount != 400 {
		t.Fatalf("unpacked document did not reach the caller: %#v", result.Beautified)
	}
	// The endpoint half of a full request still has to come from the string pass,
	// asked under the caller's profile rather than the forced beautify one.
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].URL.Rendered != "/api/v3/late" {
		t.Fatalf("string-pass endpoints were not merged in: %#v", result.RequestFacts)
	}
}

// Above the unpack ceiling there is nothing the engine can do cheaply, so the
// regex pass remains the correct tier.
func TestServiceAboveUnpackCeilingSkipsTheEngine(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 64, MaxUnpackInputBytes: 128, HardInputBytes: 8192,
	}, backend)
	defer func() { _ = service.Close() }()

	content := []byte(`fetch("/api/v3/huge");` + strings.Repeat(" ", 300))
	if _, err := service.ScanWithOptions(context.Background(), content, ScanOptions{Profile: ProfileFull}); err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("input above the unpack ceiling reached the engine %d time(s)", backend.calls.Load())
	}
}

// A profile whose product is AST-derived gains nothing from a dispatch that
// cannot parse, so it must keep short-circuiting.
func TestServiceAboveASTCeilingSkipsEngineForNonBeautifyProfiles(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 16, MaxASTInputBytes: 64, MaxUnpackInputBytes: 4096, HardInputBytes: 8192,
	}, backend)
	defer func() { _ = service.Close() }()

	content := []byte(`fetch("/api/v3/endpoints-only");` + strings.Repeat(" ", 200))
	if _, err := service.ScanWithOptions(context.Background(), content, ScanOptions{Profile: ProfileEndpoints}); err != nil {
		t.Fatal(err)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("endpoints-only profile dispatched an unparseable input %d time(s)", backend.calls.Load())
	}
}

func TestServiceParserFailureDegradesToBoundedFallback(t *testing.T) {
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		result := &ScanResult{Analysis: &AnalysisResultV2{}}
		result.Analysis.Stats.Status = "failed"
		result.Completion = &ScanCompletion{Status: "failed", ReasonCode: "ast_node_limit_reached", Profile: options.Profile}
		result.Diagnostics = []Diagnostic{{Type: "diagnostic", Severity: "error", Stage: "parse", Code: "ast_node_limit_reached"}}
		return result, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 1024, MaxASTInputBytes: 2048, HardInputBytes: 4096,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/fallback')`), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion == nil || result.Completion.Status != "partial" || result.Completion.ReasonCode != "ast_node_limit_reached_fallback" {
		t.Fatalf("failed AST result did not become an explicit partial fallback: %#v", result.Completion)
	}
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].Provenance.Confidence != "low" {
		t.Fatalf("fallback did not retain a bounded hint: %#v", result.RequestFacts)
	}
	if stats := service.Stats(); stats.FallbackJobs != 1 || stats.DegradedJobs != 1 {
		t.Fatalf("unexpected parser fallback stats: %+v", stats)
	}
}

// A failed status means the AST stages failed, not that the job produced
// nothing: beautify does not need the AST and routinely completes on an input
// whose parse was rejected. The fallback must supplement that output, never
// replace it.
func TestServiceFallbackPreservesEngineOutputOnFailedStatus(t *testing.T) {
	backend := &fakeServiceBackend{scan: func(_ context.Context, _ []byte, options ScanOptions) (*ScanResult, error) {
		result := &ScanResult{
			Beautified: &BeautifiedCode{
				Filename: "asset.js", Format: "webpack", ModuleCount: 400,
				ModulePaths: []string{"./src/api.js"}, Changed: true, Content: "// beautified",
			},
			Analysis: &AnalysisResultV2{SchemaVersion: 2},
		}
		result.Analysis.Stats.Status = "failed"
		result.Analysis.Stats.StageMetrics = []StageMetric{
			{Stage: "parse", Status: "failed"},
			{Stage: "beautify", Status: "complete", DurationMS: 5339},
		}
		result.Completion = &ScanCompletion{Status: "failed", ReasonCode: "ast_node_limit_reached", Profile: options.Profile}
		return result, nil
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 1024, MaxASTInputBytes: 2048, HardInputBytes: 4096,
	}, backend)
	defer func() { _ = service.Close() }()

	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/v3/kept')`), ScanOptions{Profile: ProfileFull})
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasBeautified() || result.Beautified.ModuleCount != 400 || result.Beautified.Format != "webpack" {
		t.Fatalf("fallback discarded the engine's beautified document: %#v", result.Beautified)
	}
	if result.Status() != "partial" {
		t.Fatalf("merged result should be partial, got %q", result.Status())
	}
	// The stage metrics are the evidence that beautify succeeded; losing them
	// leaves a caller unable to tell a rescued result from a pure regex guess.
	var beautifyRan bool
	for _, stage := range result.Analysis.Stats.StageMetrics {
		if stage.Stage == "beautify" && stage.Status == "complete" {
			beautifyRan = true
		}
	}
	if !beautifyRan {
		t.Fatalf("merged result lost the engine stage metrics: %#v", result.Analysis.Stats.StageMetrics)
	}
	if len(result.RequestFacts) != 1 || result.RequestFacts[0].Provenance.Confidence != "low" {
		t.Fatalf("fallback hint was not appended: %#v", result.RequestFacts)
	}
}

// The regex pass cannot resolve a verb, and an empty method is the schema's
// own "unresolved" convention. Emitting "GET" made a guess indistinguishable
// from a resolved method, and the replay gate reads this field directly.
func TestFallbackDoesNotFabricateAMethod(t *testing.T) {
	result := cheapFallbackAnalysis([]byte(`fetch("/api/v3/guessed")`), normalizeScanOptions(ScanOptions{Profile: ProfileEndpoints}), "hash")
	if len(result.RequestFacts) != 1 {
		t.Fatalf("expected one fallback hint, got %d", len(result.RequestFacts))
	}
	if method := result.RequestFacts[0].Method.Rendered; method != "" {
		t.Fatalf("fallback fabricated method %q; unresolved methods must be empty", method)
	}
	if result.Requests[0].Method != "" {
		t.Fatalf("legacy projection fabricated method %q", result.Requests[0].Method)
	}
}

// Merging must not duplicate a URL the engine already reported.
func TestMergeFallbackSkipsURLsTheEngineAlreadyFound(t *testing.T) {
	engine := &ScanResult{
		RequestFacts: []HTTPRequestFact{{
			Kind: "httpRequest", URL: ValueTemplate{Rendered: "/api/v3/known"},
			Method:     ValueTemplate{Rendered: "POST"},
			Provenance: Provenance{Extractor: "fetch", Confidence: "high"},
		}},
		Analysis:   &AnalysisResultV2{SchemaVersion: 2},
		Completion: &ScanCompletion{Status: "failed"},
	}
	fallback := cheapFallbackAnalysisWithReason(
		[]byte(`fetch("/api/v3/known");fetch("/api/v3/extra")`),
		normalizeScanOptions(ScanOptions{Profile: ProfileEndpoints}), "hash", "reason", "message",
	)
	mergeFallbackInto(engine, fallback, "reason")

	if len(engine.RequestFacts) != 2 {
		t.Fatalf("expected the known URL deduped and the new one appended, got %d", len(engine.RequestFacts))
	}
	if engine.RequestFacts[0].Method.Rendered != "POST" || engine.RequestFacts[0].Provenance.Extractor != "fetch" {
		t.Fatalf("merge overwrote the engine's own resolved fact: %#v", engine.RequestFacts[0])
	}
	if engine.RequestFacts[1].URL.Rendered != "/api/v3/extra" {
		t.Fatalf("merge appended the wrong fact: %#v", engine.RequestFacts[1])
	}
}

func TestServiceWorkerFailureDegradesDiscoveryButNotDOM(t *testing.T) {
	backend := &fakeServiceBackend{scan: func(context.Context, []byte, ScanOptions) (*ScanResult, error) {
		return nil, errors.New("worker crashed")
	}}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 2, CacheBytes: 1024 * 1024,
		NormalInputBytes: 1024, MaxASTInputBytes: 2048, HardInputBytes: 4096,
	}, backend)
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(context.Background(), []byte(`fetch('/api/recovered')`), ScanOptions{Profile: ProfileDiscovery})
	if err != nil || result == nil || result.Completion == nil || result.Completion.ReasonCode != "worker_failure_fallback" {
		t.Fatalf("discovery worker failure did not degrade safely: result=%#v err=%v", result, err)
	}
	if _, err := service.ScanWithOptions(context.Background(), []byte(`location.hash`), ScanOptions{Profile: ProfileDOMSecurity}); err == nil {
		t.Fatal("DOM-only worker failure was incorrectly presented as endpoint fallback")
	}
}

func TestServiceHardInputLimitRejectsBeforeBackend(t *testing.T) {
	backend := &fakeServiceBackend{}
	service := newServiceWithBackend(&ServiceConfig{
		MaxWeight: 1, HardInputBytes: 16, MaxASTInputBytes: 8, NormalInputBytes: 4,
	}, backend)
	defer func() { _ = service.Close() }()
	_, err := service.ScanWithOptions(context.Background(), make([]byte, 17), ScanOptions{Profile: ProfileEndpoints})
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("error = %v, want ErrInputTooLarge", err)
	}
	if backend.calls.Load() != 0 || service.Stats().RejectedJobs != 1 {
		t.Fatalf("hard rejection reached backend or lost metrics: calls=%d stats=%+v", backend.calls.Load(), service.Stats())
	}
}
