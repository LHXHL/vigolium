package core

import (
	"context"
	"sync"
	"sync/atomic"
)

// Tiered response buffer pools reduce GC pressure across response sizes.
// Three tiers cover the common response size distribution:
//   - small:  responses up to 1 MiB  (most responses)
//   - medium: responses up to 4 MiB  (large pages, API responses)
//   - large:  responses up to 16 MiB (very large payloads)
//
// Responses exceeding 16 MiB are allocated directly and not pooled.
const (
	poolTierSmall  = 1 << 20  // 1 MiB
	poolTierMedium = 4 << 20  // 4 MiB
	poolTierLarge  = 16 << 20 // 16 MiB
)

var (
	smallResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 32*1024) // 32 KiB initial cap
			return &b
		},
	}
	mediumResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 1<<20) // 1 MiB initial cap
			return &b
		},
	}
	largeResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 4<<20) // 4 MiB initial cap
			return &b
		},
	}
)

func getResponseBuffer(n int) []byte {
	var pool *sync.Pool
	switch {
	case n <= poolTierSmall:
		pool = &smallResponsePool
	case n <= poolTierMedium:
		pool = &mediumResponsePool
	case n <= poolTierLarge:
		pool = &largeResponsePool
	default:
		return make([]byte, n) // Too large for any pool
	}
	bp := pool.Get().(*[]byte)
	b := *bp
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}

func putResponseBuffer(buf []byte) {
	c := cap(buf)
	buf = buf[:0]
	switch {
	case c <= poolTierSmall:
		smallResponsePool.Put(&buf)
	case c <= poolTierMedium:
		mediumResponsePool.Put(&buf)
	case c <= poolTierLarge:
		largeResponsePool.Put(&buf)
		// c > poolTierLarge: let GC collect it
	}
}

// responseBufferGuard records that something still reachable may read the work
// item's pooled response buffer after the item completes, so the buffer must NOT
// go back to the pool.
//
// The case it exists for: a module that exceeds its per-module timeout (or is
// caught by phase cancellation) keeps running — a goroutine cannot be killed —
// and its scan closure still holds the item, whose response is built over the
// pooled buffer. Its wrapper meanwhile returns, the item completes, and its
// itemTracker would hand that buffer to the next item, which overwrites
// it underneath the abandoned module. The module then reads another request's
// response and can report a finding against it.
//
// Giving up pooling for such an item is the whole fix: the buffer is simply left
// for the GC, which is correct however long the abandoned goroutine runs. This
// costs one allocation on a path that has already lost a module call, and nothing
// at all on the normal path.
type responseBufferGuard struct {
	escaped atomic.Bool
}

type responseBufferGuardKey struct{}

// withResponseBufferGuard attaches g to ctx for the lifetime of one work item.
//
// Carried in the context rather than as a parameter because the two abandonment
// points sit at the bottom of the active and passive dispatch fan-outs: reaching
// them explicitly means threading a guard through runActiveStage,
// runActivePer{Host,Request,InsertionPoint} and the runPassivePer*Filtered
// helpers, about six signatures, all of which already carry this context. The
// cost of the context value is ~50 bytes and ~40ns per item, against a per-item
// baseline of a network round trip plus a record conversion — so the explicit
// form buys clarity, not speed. If a third consumer of this flag ever appears,
// prefer the parameter.
func withResponseBufferGuard(ctx context.Context, g *responseBufferGuard) context.Context {
	return context.WithValue(ctx, responseBufferGuardKey{}, g)
}

// markResponseBufferEscaped flags the current item's pooled buffer as unsafe to
// recycle. A no-op when no guard is attached (an executor path that does not own
// a pooled buffer, or a unit test calling a wrapper directly).
func markResponseBufferEscaped(ctx context.Context) {
	if g, ok := ctx.Value(responseBufferGuardKey{}).(*responseBufferGuard); ok && g != nil {
		g.escaped.Store(true)
	}
}
