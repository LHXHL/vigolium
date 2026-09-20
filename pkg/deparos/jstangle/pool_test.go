package jstangle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newRealWorkerService(t *testing.T, maxJobs int) (*Service, *WorkerPool) {
	t.Helper()
	service, err := NewService(&ServiceConfig{
		MemoryBudgetBytes: 512 * 1024 * 1024,
		MaxWeight:         4,
		CacheBytes:        -1,
		WorkerCount:       1,
		WorkerMaxJobs:     maxJobs,
		WorkerMaxRSSBytes: 2 * 1024 * 1024 * 1024,
		ScannerConfig:     &Config{MaxConcurrent: 1},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pool, ok := service.backend.(*WorkerPool)
	if !ok {
		_ = service.Close()
		t.Fatalf("backend = %T, want *WorkerPool", service.backend)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, pool
}

func TestWorkerPoolReusesProcessAcrossJobs(t *testing.T) {
	service, _ := newRealWorkerService(t, 100)
	// Twenty small jobs should pay for one Bun startup, not twenty.
	for i := 0; i < 20; i++ {
		endpoint := fmt.Sprintf("/api/item-%d", i)
		result, err := service.ScanWithOptions(context.Background(), []byte("fetch('"+endpoint+"')"), ScanOptions{Profile: ProfileEndpoints})
		if err != nil {
			t.Fatalf("scan %s: %v", endpoint, err)
		}
		if len(result.Requests) != 1 || result.Requests[0].URL != endpoint {
			t.Fatalf("requests for %s = %#v", endpoint, result.Requests)
		}
	}
	stats := service.Stats()
	if stats.Workers != 1 || stats.WorkerJobs != 20 || stats.WorkerRestarts != 0 {
		t.Fatalf("unexpected worker reuse stats: %+v", stats)
	}
}

func TestWorkerPoolRecyclesAtJobLimit(t *testing.T) {
	service, _ := newRealWorkerService(t, 1)
	for _, endpoint := range []string{"/api/first", "/api/after-recycle"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := service.ScanWithOptions(ctx, []byte("fetch('"+endpoint+"')"), ScanOptions{Profile: ProfileEndpoints})
		cancel()
		if err != nil {
			t.Fatalf("scan %s: %v", endpoint, err)
		}
	}
	stats := service.Stats()
	if stats.Workers != 1 || stats.WorkerRestarts < 2 {
		t.Fatalf("worker did not recycle at the configured limit: %+v", stats)
	}
}

// An over-budget bundle fails at parse but still beautifies: webcrack works on
// source, not on the AST. The pool used to turn that "failed" completion into a
// transport error and drop the envelope, so the beautified document - the whole
// point of the call - never reached the caller.
func TestWorkerPoolReturnsEnvelopeWhenASTBudgetFails(t *testing.T) {
	service, _ := newRealWorkerService(t, 100)

	// A webpack-5 bundle padded past the node budget set below.
	var modules strings.Builder
	modules.WriteString(`100:(e,t,r)=>{t.list=function(){return fetch("/api/v3/users",{method:"POST"})}}`)
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&modules, `,%d:(e,t,r)=>{function f%d(a,b){var c=a|0,d=b>>>2;for(var h=0;h<d;h++){c=(c<<5)-c+d|0}return c}t.g=f%d}`, 200+i, i, i)
	}
	bundle := `(()=>{"use strict";var e={` + modules.String() + `},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}var n=r(100);console.log(n)})();`

	result, err := service.ScanWithOptions(context.Background(), []byte(bundle), ScanOptions{
		Profile: ProfileFull, Beautify: true, MaxASTNodes: 1000,
	})
	if err != nil {
		t.Fatalf("an over-budget bundle must return a degraded result, not an error: %v", err)
	}
	if !result.HasBeautified() {
		t.Fatal("the beautified document was discarded by the failed-status path")
	}
	if result.Beautified.Format != "webpack" || result.Beautified.ModuleCount == 0 {
		t.Fatalf("beautified document is not the unpacked bundle: %#v", result.Beautified)
	}
	if status := result.Status(); status != "partial" {
		t.Fatalf("status = %q, want partial after the fallback merge", status)
	}
	var sawBudget bool
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == "ast_node_limit_reached" {
			sawBudget = true
		}
	}
	if !sawBudget {
		t.Fatalf("the engine's own diagnostics were lost: %#v", result.Diagnostics)
	}
}

// The module scan was opt-in behind a flag no Go caller could send: the option
// existed on the engine and the worker read it, but the request struct had no
// field for it. Reaching it deliberately - rather than only as budget recovery -
// requires the option to survive the whole transport.
func TestWorkerPoolPassesUnpackModulesThrough(t *testing.T) {
	service, _ := newRealWorkerService(t, 100)

	// Padded past looksWorthBeautifying's 500-byte floor, which gates the stage
	// before any option is consulted.
	var filler strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&filler, `,%d:(e,t)=>{t.p%d=function(a,b){var c=a|0,d=b>>>2;for(var h=0;h<d;h++){c=(c<<5)-c+d|0}return c}}`, 300+i, i)
	}
	bundle := `(()=>{"use strict";var e={` +
		`100:(e,t,r)=>{const n=r(200);t.listUsers=function(){return fetch(n.base+"/users",{method:"GET"})}},` +
		`200:(e,t)=>{t.base="/api/v3"}` + filler.String() + `},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}var n=r(100);console.log(n)})();`

	withFlag, err := service.ScanWithOptions(context.Background(), []byte(bundle), ScanOptions{
		Profile: ProfileEndpoints, UnpackModules: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawModuleProvenance bool
	for i := range withFlag.RequestFacts {
		if withFlag.RequestFacts[i].Provenance.ModulePath != "" {
			sawModuleProvenance = true
		}
	}
	if !sawModuleProvenance {
		t.Fatalf("unpackModules did not reach the engine; no module-path provenance: %#v", withFlag.RequestFacts)
	}

	// And the option must still be an option: an in-budget bundle without it
	// pays for no webcrack pass.
	without, err := service.ScanWithOptions(context.Background(), []byte(bundle), ScanOptions{
		Profile: ProfileEndpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range without.RequestFacts {
		if without.RequestFacts[i].Provenance.ModulePath != "" {
			t.Fatalf("module scan ran without being asked: %#v", without.RequestFacts[i].Provenance)
		}
	}
}

// UnpackModules and MaxBundleModules change what the engine produces, so a run
// under one setting must not be served from a run under another.
func TestServiceCacheKeyIncludesBundleOptions(t *testing.T) {
	content := []byte(`fetch("/api/v3/cached")`)
	base := normalizeScanOptions(ScanOptions{Profile: ProfileEndpoints})
	unpacked := base
	unpacked.UnpackModules = true
	capped := base
	capped.MaxBundleModules = 32

	plainKey := serviceCacheKey(content, base, "hash")
	if unpackedKey := serviceCacheKey(content, unpacked, "hash"); unpackedKey == plainKey {
		t.Fatal("UnpackModules is absent from the cache key; results would collide across settings")
	}
	if cappedKey := serviceCacheKey(content, capped, "hash"); cappedKey == plainKey {
		t.Fatal("MaxBundleModules is absent from the cache key; results would collide across settings")
	}
}

func TestWorkerPoolRetriesOnceAfterCrash(t *testing.T) {
	service, pool := newRealWorkerService(t, 10)
	if err := pool.ensureStarted(); err != nil {
		t.Fatalf("start pool: %v", err)
	}
	worker := <-pool.available
	worker.stop(false)
	pool.available <- worker

	result, err := service.ScanWithOptions(context.Background(), []byte("fetch('/api/recovered')"), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatalf("scan after worker crash: %v", err)
	}
	if len(result.Requests) != 1 || result.Requests[0].URL != "/api/recovered" {
		t.Fatalf("unexpected recovered result: %#v", result.Requests)
	}
	stats := service.Stats()
	if stats.WorkerRetries != 1 || stats.WorkerRestarts < 1 || stats.Workers != 1 {
		t.Fatalf("unexpected crash recovery stats: %+v", stats)
	}
}

func TestWorkerPoolCancellationKillsAndReplacesActiveWorker(t *testing.T) {
	service, pool := newRealWorkerService(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	largeSource := strings.Repeat("const sufficientlyLongName = 123456;\n", 100_000)
	go func() {
		_, err := service.ScanWithOptions(ctx, []byte(largeSource), ScanOptions{Profile: ProfileFull})
		done <- err
	}()

	deadline := time.Now().Add(20 * time.Second)
	for pool.Stats().ActiveJobs == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pool.Stats().ActiveJobs == 0 {
		t.Fatal("worker job did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan error = %v, want context.Canceled", err)
	}

	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer recoveryCancel()
	result, err := service.ScanWithOptions(recoveryCtx, []byte("fetch('/api/after-cancel')"), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatalf("scan after cancellation: %v", err)
	}
	if len(result.Requests) != 1 || result.Requests[0].URL != "/api/after-cancel" {
		t.Fatalf("unexpected post-cancellation result: %#v", result.Requests)
	}
	if stats := service.Stats(); stats.WorkerRestarts < 1 || stats.Workers != 1 {
		t.Fatalf("cancelled worker was not replaced: %+v", stats)
	}
}
