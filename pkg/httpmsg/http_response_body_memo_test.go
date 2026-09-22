package httpmsg

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

func newRespWithBody(body string) *HttpResponse {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
		intToString(len(body)) + "\r\n\r\n" + body
	return NewHttpResponse([]byte(raw))
}

func TestBodyMemo_Correctness(t *testing.T) {
	const body = "Hello WORLD <Script>AbC</Script>"
	r := newRespWithBody(body)

	if got := r.BodyToString(); got != body {
		t.Fatalf("BodyToString = %q, want %q", got, body)
	}
	// Repeated call returns the same content (memoized).
	if got := r.BodyToString(); got != body {
		t.Fatalf("BodyToString (2nd) = %q, want %q", got, body)
	}
	wantLower := strings.ToLower(body)
	if got := r.BodyLowerString(); got != wantLower {
		t.Fatalf("BodyLowerString = %q, want %q", got, wantLower)
	}
}

func TestBodyMemo_InvalidatedByTruncate(t *testing.T) {
	const body = "ABCDEFghij"
	r := newRespWithBody(body)

	// Populate the caches.
	if r.BodyToString() != body || r.BodyLowerString() != strings.ToLower(body) {
		t.Fatal("setup: unexpected pre-truncate body")
	}

	r.TruncateBody(3) // keep "ABC"

	if got := r.BodyToString(); got != "ABC" {
		t.Fatalf("BodyToString after truncate = %q, want %q", got, "ABC")
	}
	if got := r.BodyLowerString(); got != "abc" {
		t.Fatalf("BodyLowerString after truncate = %q, want %q", got, "abc")
	}
}

func TestBodyMemo_ConcurrentReadsRaceFree(t *testing.T) {
	const body = "Concurrent BODY content For Race Testing"
	r := newRespWithBody(body)
	wantLower := strings.ToLower(body)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.BodyToString() != body {
				t.Error("BodyToString mismatch under concurrency")
			}
			if r.BodyLowerString() != wantLower {
				t.Error("BodyLowerString mismatch under concurrency")
			}
		}()
	}
	wg.Wait()
}

// TestBodyMemo_ColdHerdComputesOnce is the reason BodyToString resolves its miss
// under the write lock. The interesting property is not that concurrent readers
// agree — the pre-existing shape managed that too — but that they do not each
// copy the body to produce one shared answer.
//
// Measured in bytes rather than by counting calls, because the copy is an
// internal detail with no seam to instrument. With a 1 MiB body and 64 readers
// released together, resolving the miss once costs about 1 MiB; the
// compute-outside-the-lock shape this replaced cost up to 64.
func TestBodyMemo_ColdHerdComputesOnce(t *testing.T) {
	const (
		bodySize = 1 << 20 // 1 MiB
		readers  = 64
		// Generous next to one copy, far under the many this used to make.
		budget = 8 * bodySize
	)
	body := strings.Repeat("A", bodySize)
	r := newRespWithBody(body)

	// Parse before measuring: header parsing is a fixed cost either way, and
	// leaving it inside the window charges it to the result.
	r.ensureParsed()

	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(readers)
	done.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start // release every reader into the cold cache together
			if len(r.BodyToString()) != bodySize {
				t.Error("BodyToString returned a short body")
			}
		}()
	}
	ready.Wait()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	close(start)
	done.Wait()
	runtime.ReadMemStats(&after)

	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > budget {
		t.Errorf("cold herd of %d readers allocated %d bytes for a %d-byte body; "+
			"want under %d (one shared copy)", readers, allocated, bodySize, budget)
	}
}

// TestBodyMemo_LowerSharesTheBodyCopy pins the other half: a cold
// BodyLowerString must not copy the body once for itself and again for
// BodyToString's cache. It goes through bodyStringLocked, so the two caches are
// populated from a single copy plus one lowering.
func TestBodyMemo_LowerSharesTheBodyCopy(t *testing.T) {
	const bodySize = 1 << 20
	body := strings.Repeat("A", bodySize)
	r := newRespWithBody(body)
	r.ensureParsed()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_ = r.BodyLowerString()
	runtime.ReadMemStats(&after)

	// One body copy + one lowered copy, with slack for the runtime's size
	// classes; a third copy would blow past this.
	const budget = 3 * bodySize
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > budget {
		t.Errorf("cold BodyLowerString allocated %d bytes for a %d-byte body; want under %d",
			allocated, bodySize, budget)
	}
	// And the body cache is now populated from that same copy.
	if got := r.BodyToString(); len(got) != bodySize {
		t.Errorf("BodyToString after BodyLowerString returned %d bytes, want %d", len(got), bodySize)
	}
}
