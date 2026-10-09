package jstangle

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const mib = int64(1024 * 1024)

func TestDefaultWorkerCount(t *testing.T) {
	cases := []struct {
		name   string
		budget int64
		cpus   int
		want   int
	}{
		// Under 768 MiB there is room for one worker; the floor of two yields.
		{"512MiB budget", 512 * mib, 10, 1},
		{"768MiB budget gives the floor", 768 * mib, 10, 2},
		{"768MiB on a 2-core box", 768 * mib, 2, 2},
		{"4GiB on 10 cores is cpu-bound", 4096 * mib, 10, 5},
		{"4GiB on 64 cores hits the cap", 4096 * mib, 64, 8},
		{"2GiB on 16 cores is budget-bound", 2048 * mib, 16, 5},
		{"tiny budget still runs one worker", 64 * mib, 8, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultWorkerCount(tc.budget, tc.cpus); got != tc.want {
				t.Fatalf("defaultWorkerCount(%d MiB, %d cpus) = %d, want %d", tc.budget/mib, tc.cpus, got, tc.want)
			}
		})
	}
}

func TestServiceMemoryBudgetFor(t *testing.T) {
	gib := uint64(1024 * 1024 * 1024)
	cases := []struct {
		total uint64
		want  int64
	}{
		{0, 768 * mib},         // unknown RAM: the floor
		{4 * gib, 768 * mib},   // 512 MiB share, floored
		{8 * gib, 1024 * mib},  // 1 GiB share
		{16 * gib, 2048 * mib}, // 2 GiB share
		{64 * gib, 2048 * mib}, // capped
	}
	for _, tc := range cases {
		if got := serviceMemoryBudgetFor(tc.total); got != tc.want {
			t.Errorf("serviceMemoryBudgetFor(%d GiB) = %d MiB, want %d MiB", tc.total/gib, got/mib, tc.want/mib)
		}
	}
}

func TestResolveServiceConfigDerivesWorkersFromBudget(t *testing.T) {
	restore := numCPU
	numCPU = func() int { return 10 }
	defer func() { numCPU = restore }()

	resolved := resolveServiceConfig(&ServiceConfig{MemoryBudgetBytes: 4096 * mib})
	if resolved.WorkerCount != 5 {
		t.Fatalf("WorkerCount = %d, want 5", resolved.WorkerCount)
	}
	if resolved.MaxWeight != 32 {
		t.Fatalf("MaxWeight = %d, want 32", resolved.MaxWeight)
	}
	explicit := resolveServiceConfig(&ServiceConfig{MemoryBudgetBytes: 4096 * mib, WorkerCount: 3})
	if explicit.WorkerCount != 3 {
		t.Fatalf("explicit WorkerCount = %d, want 3", explicit.WorkerCount)
	}
	if resolved.HardInputBytes != 16*mib || resolved.MaxUnpackInputBytes != 16*mib || resolved.MaxASTInputBytes != 4*mib {
		t.Fatalf("default tiers = hard %d / unpack %d / ast %d MiB, want 16/16/4",
			resolved.HardInputBytes/mib, resolved.MaxUnpackInputBytes/mib, resolved.MaxASTInputBytes/mib)
	}
	clamped := resolveServiceConfig(&ServiceConfig{HardInputBytes: 10 * mib})
	if clamped.MaxUnpackInputBytes != 10*mib {
		t.Fatalf("unpack tier = %d MiB, want it clamped to the 10 MiB hard limit", clamped.MaxUnpackInputBytes/mib)
	}
}

// swapDefaultService installs a fake running default service and restores the
// package globals afterwards.
func swapDefaultService(t *testing.T, active ServiceConfig) {
	t.Helper()
	defaultServiceMu.Lock()
	savedService, savedErr, savedConfig := defaultService, defaultServiceErr, defaultServiceConfig
	savedActive, savedWarned := activeServiceConfig, configMismatchWarned
	defaultService = testService(&fakeServiceBackend{}, 1, 0)
	defaultServiceErr = nil
	activeServiceConfig = active
	configMismatchWarned = map[string]bool{}
	defaultServiceMu.Unlock()
	t.Cleanup(func() {
		defaultServiceMu.Lock()
		_ = defaultService.Close()
		defaultService, defaultServiceErr, defaultServiceConfig = savedService, savedErr, savedConfig
		activeServiceConfig, configMismatchWarned = savedActive, savedWarned
		defaultServiceMu.Unlock()
	})
}

func TestConfigureDefaultServiceAfterInitWarnsOnceNamingKeys(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	defer restoreLogger()

	// A kit/passive-module caller initialized the service with defaults.
	active := resolveServiceConfig(&ServiceConfig{MemoryBudgetBytes: 768 * mib})
	swapDefaultService(t, active)

	// The same settings again are a no-op, not a mismatch.
	if err := ConfigureDefaultService(&ServiceConfig{MemoryBudgetBytes: 768 * mib}); err != nil {
		t.Fatalf("identical configure returned %v", err)
	}

	discovery := &ServiceConfig{MemoryBudgetBytes: 768 * mib, WorkerCount: 4, HardInputBytes: 32 * mib, MaxUnpackInputBytes: 32 * mib}
	for range 3 {
		err := ConfigureDefaultService(discovery)
		if !errors.Is(err, ErrDefaultServiceConfigured) {
			t.Fatalf("error = %v, want ErrDefaultServiceConfigured", err)
		}
		for _, key := range []string{"worker_count=2 (requested 4)", "hard_input_mb=16 (requested 32)", "max_unpack_input_mb"} {
			if !strings.Contains(err.Error(), key) {
				t.Fatalf("error %q does not name %q", err, key)
			}
		}
	}
	if logs.Len() != 1 {
		t.Fatalf("warnings = %d, want exactly one for a repeated mismatch", logs.Len())
	}
	entry := logs.All()[0]
	keys, _ := entry.ContextMap()["keys"].([]interface{})
	if len(keys) != 3 {
		t.Fatalf("warning keys = %v, want worker_count, max_unpack_input_mb, hard_input_mb", entry.ContextMap()["keys"])
	}

	// A different mismatch is its own warning.
	_ = ConfigureDefaultService(&ServiceConfig{MemoryBudgetBytes: 1024 * mib, WorkerCount: 2})
	if logs.Len() != 2 {
		t.Fatalf("warnings = %d, want a second warning for a new key set", logs.Len())
	}

	got, initialized := ActiveServiceConfig()
	if !initialized || got.WorkerCount != 2 || got.HardInputBytes != 16*mib {
		t.Fatalf("ActiveServiceConfig = %+v (initialized=%v), want the running defaults", got, initialized)
	}
}

func TestActiveServiceConfigBeforeInitReportsPending(t *testing.T) {
	defaultServiceMu.Lock()
	if defaultService != nil || defaultServiceErr != nil {
		defaultServiceMu.Unlock()
		t.Skip("default service already initialized in this test binary")
	}
	saved := defaultServiceConfig
	defaultServiceMu.Unlock()
	defer func() {
		defaultServiceMu.Lock()
		defaultServiceConfig = saved
		defaultServiceMu.Unlock()
	}()

	if err := ConfigureDefaultService(&ServiceConfig{MemoryBudgetBytes: 768 * mib, WorkerCount: 3}); err != nil {
		t.Fatal(err)
	}
	got, initialized := ActiveServiceConfig()
	if initialized || got.WorkerCount != 3 || got.MemoryBudgetBytes != 768*mib {
		t.Fatalf("ActiveServiceConfig = workers %d budget %d MiB initialized=%v, want pending 3/768/false",
			got.WorkerCount, got.MemoryBudgetBytes/mib, initialized)
	}
}

func TestServiceInputPolicyBandsAtDefaultTiers(t *testing.T) {
	service := newServiceWithBackend(&ServiceConfig{MaxWeight: 1}, &fakeServiceBackend{})
	defer func() { _ = service.Close() }()

	cases := []struct {
		sizeMiB int64
		profile AnalysisProfile
		want    serviceInputPolicy
	}{
		{3, ProfileDiscovery, inputPolicyLarge},
		{3, ProfileFull, inputPolicyNormal},
		{8, ProfileDiscovery, inputPolicyFallback},
		{8, ProfileBeautify, inputPolicyUnpackOnly},
		// The 10-16 MiB band used to be dead: hard (10) sat below unpack (16).
		{14, ProfileFull, inputPolicyUnpackOnly},
		{14, ProfileDiscovery, inputPolicyFallback},
	}
	for _, tc := range cases {
		if got := service.inputPolicy(tc.profile, int(tc.sizeMiB*mib)); got != tc.want {
			t.Errorf("inputPolicy(%s, %d MiB) = %d, want %d", tc.profile, tc.sizeMiB, got, tc.want)
		}
	}

	_, err := service.ScanWithOptions(context.Background(), make([]byte, 20*mib), ScanOptions{Profile: ProfileFull})
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("20 MiB error = %v, want ErrInputTooLarge", err)
	}
	if hits := service.Stats().LimitHits[limitCodeInputOverHard]; hits != 1 {
		t.Fatalf("LimitHits[%s] = %d, want 1 so the skip is not silent", limitCodeInputOverHard, hits)
	}
}
