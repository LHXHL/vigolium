package modkit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func memoTestItem(path string) *httpmsg.HttpRequestResponse {
	raw := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true), raw)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// The point of the memo: every insertion point on a record probes the same
// unmodified request, so the round-trips are paid once.
func TestEndpointMeasurement_MeasuresOncePerEndpoint(t *testing.T) {
	sc := &ScanContext{}
	item := memoTestItem("/a")

	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		return 7
	}

	for i := 0; i < 20; i++ {
		if got := sc.EndpointMeasurement("m", item, measure); got != 7 {
			t.Fatalf("call %d returned %d, want 7", i, got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("measured %d times, want exactly 1", n)
	}
}

// Distinct endpoints must not share a measurement.
func TestEndpointMeasurement_SeparatesEndpoints(t *testing.T) {
	sc := &ScanContext{}

	if got := sc.EndpointMeasurement("m", memoTestItem("/a"), func() int { return 1 }); got != 1 {
		t.Fatalf("endpoint /a = %d, want 1", got)
	}
	if got := sc.EndpointMeasurement("m", memoTestItem("/b"), func() int { return 2 }); got != 2 {
		t.Fatalf("endpoint /b = %d, want 2", got)
	}
	if got := sc.EndpointMeasurement("m", memoTestItem("/a"), func() int { return 99 }); got != 1 {
		t.Fatalf("endpoint /a re-read = %d, want cached 1", got)
	}
}

// Two measurements on the SAME record must not collide — that is what the name
// namespace is for.
func TestEndpointMeasurement_SeparatesNames(t *testing.T) {
	sc := &ScanContext{}
	item := memoTestItem("/shared")

	if got := sc.EndpointMeasurement("jitter", item, func() int { return 1 }); got != 1 {
		t.Fatalf("jitter = %d, want 1", got)
	}
	if got := sc.EndpointMeasurement("timing", item, func() int { return 2 }); got != 2 {
		t.Fatalf("timing = %d, want 2 (must not read jitter's entry)", got)
	}
}

// The executor dispatches a record's insertion points concurrently, so the
// misses all land at the same instant. Without singleflight each would run its
// own probes — the exact cost this memo removes.
func TestEndpointMeasurement_CoalescesConcurrent(t *testing.T) {
	sc := &ScanContext{}
	item := memoTestItem("/concurrent")

	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond) // hold the flight open so others pile on
		return 3
	}

	var wg sync.WaitGroup
	results := make([]int, 20)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = sc.EndpointMeasurement("m", item, measure)
		}(i)
	}
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("measured %d times under concurrency, want exactly 1", n)
	}
	for i, got := range results {
		if got != 3 {
			t.Fatalf("goroutine %d got %d, want 3", i, got)
		}
	}
}

// A nil ScanContext or unidentifiable request must measure directly rather than
// share a degenerate key.
func TestEndpointMeasurement_FallsBackWithoutIdentity(t *testing.T) {
	var calls atomic.Int32
	measure := func() int {
		calls.Add(1)
		return 5
	}

	var nilSC *ScanContext
	for i := 0; i < 3; i++ {
		if got := nilSC.EndpointMeasurement("m", memoTestItem("/x"), measure); got != 5 {
			t.Fatalf("nil ScanContext returned %d, want 5", got)
		}
	}
	sc := &ScanContext{}
	for i := 0; i < 3; i++ {
		if got := sc.EndpointMeasurement("m", nil, measure); got != 5 {
			t.Fatalf("nil ctx returned %d, want 5", got)
		}
	}
	if n := calls.Load(); n != 6 {
		t.Fatalf("measured %d times, want 6 (no shared key in either fallback)", n)
	}
}

func TestHostMemo_ComputesOncePerHost(t *testing.T) {
	sc := &ScanContext{}
	var calls atomic.Int32
	compute := func() any {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond) // widen the race window for the singleflight
		return []string{"k1"}
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _ := sc.HostMemo("jwks", "Example.com:443", compute).([]string)
			if len(got) != 1 || got[0] != "k1" {
				t.Errorf("unexpected memo value %v", got)
			}
		}()
	}
	wg.Wait()
	sc.HostMemo("jwks", "example.com:443", compute) // host is case-insensitive
	if n := calls.Load(); n != 1 {
		t.Fatalf("computed %d times, want 1", n)
	}

	// A different host or name is a different artifact.
	sc.HostMemo("jwks", "other.example:443", compute)
	sc.HostMemo("oidc", "example.com:443", compute)
	if n := calls.Load(); n != 3 {
		t.Fatalf("computed %d times, want 3", n)
	}
}

func TestHostMemo_CachesEmptyResultAndNilContext(t *testing.T) {
	sc := &ScanContext{}
	var calls atomic.Int32
	compute := func() any { calls.Add(1); return nil }
	sc.HostMemo("jwks", "h", compute)
	sc.HostMemo("jwks", "h", compute)
	if n := calls.Load(); n != 1 {
		t.Fatalf("a nil result must be cached too; computed %d times", n)
	}

	var nilSC *ScanContext
	if v := nilSC.HostMemo("jwks", "h", func() any { return 3 }); v != 3 {
		t.Fatalf("nil ScanContext should compute directly, got %v", v)
	}
}
