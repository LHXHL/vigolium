package jstangle

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// growingBackend is a fake pool that records Grow calls and, like the real
// pool, never lowers its worker count.
type growingBackend struct {
	fakeServiceBackend
	mu      sync.Mutex
	workers int
	calls   []int
}

func (b *growingBackend) Grow(workers int) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, workers)
	b.workers = max(b.workers, workers)
	return b.workers, nil
}

// TestServiceGrowRaisesAdmissionMidFlight: a Grow while a heavy job holds the
// whole of the old admission lets a new job in at once, the job already queued
// on the old gate still completes, and every unit of weight comes back to the
// gate it was taken from.
func TestServiceGrowRaisesAdmissionMidFlight(t *testing.T) {
	started := make(chan string, 3)
	release := make(chan struct{})
	backend := &fakeServiceBackend{scan: func(ctx context.Context, content []byte, _ ScanOptions) (*ScanResult, error) {
		started <- string(content)
		select {
		case <-release:
			return &ScanResult{Requests: []ExtractedRequest{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	// Capacity 2 and an endpoints job weighs 3 (clamped to 2): one at a time.
	service := testService(backend, 2, 0)
	defer func() { _ = service.Close() }()
	oldGate := service.gate.Load()

	var wg sync.WaitGroup
	scan := func(content string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := service.ScanWithOptions(context.Background(), []byte(content), ScanOptions{Profile: ProfileEndpoints}); err != nil {
				t.Errorf("scan %s: %v", content, err)
			}
		}()
	}

	scan("holder")
	if got := <-started; got != "holder" {
		t.Fatalf("first job = %q", got)
	}
	scan("queued-on-old-gate")
	select {
	case got := <-started:
		t.Fatalf("%q started while the old gate was full", got)
	case <-time.After(50 * time.Millisecond):
	}

	// Six weight units: two endpoint jobs (3 each) fit side by side.
	workers, maxWeight, err := service.Grow(4, 6*serviceWeightBytes)
	if err != nil || maxWeight != 6 || workers != 0 {
		t.Fatalf("Grow = (%d, %d, %v), want (0 without a pool, 6, nil)", workers, maxWeight, err)
	}
	scan("after-grow")
	select {
	case got := <-started:
		if got != "after-grow" {
			t.Fatalf("started %q, want the job admitted by the grown gate", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a job submitted after Grow was not admitted while the old gate was full")
	}

	// Growing to less is a no-op.
	if _, maxWeight, _ := service.Grow(1, serviceWeightBytes); maxWeight != 6 {
		t.Fatalf("Grow to a smaller budget left capacity %d, want it kept at 6", maxWeight)
	}

	close(release)
	wg.Wait()
	if !oldGate.sem.TryAcquire(oldGate.max) {
		t.Fatal("the old gate did not get its weight back")
	}
	if newGate := service.gate.Load(); !newGate.sem.TryAcquire(newGate.max) {
		t.Fatal("the grown gate did not get its weight back")
	}
}

// TestConfigureDefaultServiceGrowsForLargerRequest: a discovery engine that
// asks for more workers or memory than the kit/passive-module caller that
// started the shared service gets them, and only what cannot be grown (a
// smaller value, an input tier) is still reported as a mismatch.
func TestConfigureDefaultServiceGrowsForLargerRequest(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	defer restoreLogger()

	active := resolveServiceConfig(&ServiceConfig{MemoryBudgetBytes: 768 * mib, WorkerCount: 2})
	backend := &growingBackend{workers: 2}
	service := newServiceWithBackend(&active, backend)
	swapDefaultServiceWith(t, active, service)

	if err := ConfigureDefaultService(&ServiceConfig{MemoryBudgetBytes: 1024 * mib, WorkerCount: 4}); err != nil {
		t.Fatalf("a larger request should be grown into, not rejected: %v", err)
	}
	got, initialized := ActiveServiceConfig()
	if !initialized || got.WorkerCount != 4 || got.MemoryBudgetBytes != 1024*mib || got.MaxWeight != 8 {
		t.Fatalf("ActiveServiceConfig = workers %d budget %d MiB weight %d, want 4/1024/8",
			got.WorkerCount, got.MemoryBudgetBytes/mib, got.MaxWeight)
	}
	if gate := service.gate.Load(); gate.max != 8 {
		t.Fatalf("admission capacity = %d, want 8", gate.max)
	}
	if logs.Len() != 0 {
		t.Fatalf("growing must not warn: %v", logs.All())
	}

	// Asking for fewer workers never shrinks the pool; it is a mismatch.
	err := ConfigureDefaultService(&ServiceConfig{MemoryBudgetBytes: 1024 * mib, WorkerCount: 3})
	if !errors.Is(err, ErrDefaultServiceConfigured) || !strings.Contains(err.Error(), "worker_count=4 (requested 3)") {
		t.Fatalf("error = %v, want a worker_count mismatch naming the running 4", err)
	}
	if backend.workers != 4 {
		t.Fatalf("pool workers = %d after a smaller request, want 4", backend.workers)
	}
}
