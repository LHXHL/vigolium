package responsechain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// getWithin takes one buffer from the pool, giving up after d. It exists so the
// drain in availablePermits can charge its deadline per acquisition.
func getWithin(d time.Duration) (*bytes.Buffer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return bufPool.Get(ctx)
}

// availablePermits counts how many slots bufPool can still hand out, by draining
// it with an already-expired context and putting everything straight back.
//
// SizedPool.Size() reports the CONFIGURED capacity and never moves on
// acquire/release, so it cannot observe a leak; only the free count can.
func availablePermits(t *testing.T) int {
	t.Helper()
	// The deadline is PER Get, never one budget shared across the whole drain.
	// Every Get that finds a free slot returns immediately, so only the final one
	// — the one proving nothing is left — waits its budget out; the drain itself
	// is then unbounded and cannot be cut short. A single shared deadline made
	// this flaky: the ~10k slots take ~12ms to drain under -race on an idle
	// machine, and under the full suite's parallel load that overran a 30ms
	// budget, ending the loop at an arbitrary count so `before` and `after`
	// compared two unrelated numbers.
	//
	// It must be a LIVE deadline, not an already-cancelled context:
	// x/sync/semaphore.Acquire checks ctx.Done() before it checks availability,
	// so a pre-cancelled context fails on the very first call and would make this
	// always report 0. (Shrinking the pool first would be cheaper, but
	// ChangePoolSize with a negative delta panics inside utils@v0.11.1 —
	// Semaphore.Vary passes the negative n straight to Acquire.)
	var held []*bytes.Buffer
	for {
		buf, err := getWithin(20 * time.Millisecond)
		if err != nil {
			break
		}
		held = append(held, buf)
		if len(held) > int(GetPoolSize())+1 {
			t.Fatalf("drained more buffers (%d) than the pool's capacity", len(held))
		}
	}
	for _, buf := range held {
		bufPool.Put(buf)
	}
	if len(held) == 0 {
		t.Fatal("measured 0 available permits; the probe is not working")
	}
	return len(held)
}

// assertNoPermitLeak runs op and checks the pool's free count is unchanged.
func assertNoPermitLeak(t *testing.T, name string, op func()) {
	t.Helper()
	before := availablePermits(t)
	op()
	if after := availablePermits(t); after != before {
		t.Errorf("%s: free permits went %d → %d; the discard path leaked %d slot(s)",
			name, before, after, before-after)
	}
}

// TestPutBufferReleasesPermitOnOversizedDiscard pins the discard path that leaked
// a sizedpool slot. sizedpool acquires in Get and releases only in Put/Discard, so
// dropping the buffer without Discard permanently shrinks pool capacity — enough
// of them and getBuffer blocks forever on an uncancellable Background acquire.
func TestPutBufferReleasesPermitOnOversizedDiscard(t *testing.T) {
	assertNoPermitLeak(t, "oversized discard", func() {
		if _, err := bufPool.Get(context.Background()); err != nil {
			t.Fatalf("priming Get: %v", err)
		}
		// A buffer over DefaultMaxBodySize takes the "too large to pool" path.
		putBuffer(bytes.NewBuffer(make([]byte, 0, DefaultMaxBodySize+1)))
	})
}

// TestPutBufferReleasesPermitWhenLargePoolFull covers the second discard path:
// a large buffer arriving while largeBufferSem is saturated.
func TestPutBufferReleasesPermitWhenLargePoolFull(t *testing.T) {
	// Saturate the large-buffer semaphore so the select below takes default.
	filled := 0
	for {
		select {
		case largeBufferSem <- struct{}{}:
			filled++
			continue
		default:
		}
		break
	}
	defer func() {
		for range filled {
			<-largeBufferSem
		}
	}()

	assertNoPermitLeak(t, "full large-buffer pool discard", func() {
		if _, err := bufPool.Get(context.Background()); err != nil {
			t.Fatalf("priming Get: %v", err)
		}
		putBuffer(bytes.NewBuffer(make([]byte, 0, largeBufferThreshold+1)))
	})
}

// TestSetMaxLargeBuffersUsesItsArgument guards the setter that compared a global
// against itself and ignored the value it was given.
func TestSetMaxLargeBuffersUsesItsArgument(t *testing.T) {
	original := maxLargeBuffers
	defer SetMaxLargeBuffers(original)

	SetMaxLargeBuffers(original + 7)
	if maxLargeBuffers != original+7 {
		t.Errorf("maxLargeBuffers = %d, want %d", maxLargeBuffers, original+7)
	}
	// Below the floor clamps rather than shrinking past the documented minimum.
	SetMaxLargeBuffers(1)
	if maxLargeBuffers != DefaultMaxLargeBuffers {
		t.Errorf("maxLargeBuffers = %d, want the %d floor", maxLargeBuffers, DefaultMaxLargeBuffers)
	}
}

// trackingBody reports whether it was closed.
type trackingBody struct {
	io.Reader
	closed bool
	err    error
}

func (b *trackingBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	return b.Reader.Read(p)
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

// TestFillClosesBodyOnReadError is the regression guard for the leaked network
// connection: Fill returned on a body-read failure before draining, and the
// chain's Close only returns pooled buffers, so the response body stayed open.
func TestFillClosesBodyOnReadError(t *testing.T) {
	body := &trackingBody{Reader: bytes.NewReader(nil), err: errors.New("truncated")}
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       body,
		Request:    httptestRequest(t),
	}

	rc := NewResponseChain(resp, 0)
	defer rc.Close()

	if err := rc.Fill(); err == nil {
		t.Fatal("expected Fill to fail on a read error")
	}
	if !body.closed {
		t.Error("Fill returned on a read error without closing the response body (connection leak)")
	}
}

func httptestRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}
