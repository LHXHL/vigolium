package core

import (
	"sync"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/http"
)

// baselineFailureCap bounds how many baseline failures an executor keeps. The
// question they answer is "why did nothing answer", and a handful of examples
// answers it; a host sweep over thousands of dead hosts must not retain one
// entry per host.
const baselineFailureCap = 16

// baselineFailureDetailMax clips the stored error text: a wrapped transport
// error can carry a long chain, and the detail ends up in scan documents.
const baselineFailureDetailMax = 256

// BaselineFailure is one baseline fetch that got no HTTP answer.
type BaselineFailure struct {
	// Target is the request URL that was attempted.
	Target string `json:"target"`
	// Class is the transport error class, one of the http.TransportErr*
	// constants (dns, refused, timeout, tls, reset, other).
	Class string `json:"class"`
	// Detail is the error text, truncated.
	Detail string `json:"detail"`
}

// baselineFailureRing keeps the most recent baselineFailureCap failures.
// Workers write it concurrently, so it is mutex-guarded; it is written only on
// the failure path, never per successful request.
type baselineFailureRing struct {
	mu   sync.Mutex
	buf  []BaselineFailure
	next int // slot the next write goes to once buf is full
}

func (r *baselineFailureRing) add(f BaselineFailure) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < baselineFailureCap {
		r.buf = append(r.buf, f)
		return
	}
	r.buf[r.next] = f
	r.next = (r.next + 1) % baselineFailureCap
}

// snapshot returns the retained failures oldest first, or nil when there are none.
func (r *baselineFailureRing) snapshot() []BaselineFailure {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	out := make([]BaselineFailure, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

// recordBaselineFailure classifies and keeps one failed baseline fetch.
func (e *Executor) recordBaselineFailure(target string, err error) {
	if err == nil {
		return
	}
	detail := err.Error()
	if len(detail) > baselineFailureDetailMax {
		cut := baselineFailureDetailMax
		for cut > 0 && !utf8.RuneStart(detail[cut]) {
			cut--
		}
		detail = detail[:cut]
	}
	e.baselineFailures.add(BaselineFailure{
		Target: target,
		Class:  http.ClassifyTransportError(err),
		Detail: detail,
	})
}

// BaselineFailures returns the most recent baseline fetches that got no HTTP
// answer (at most 16), oldest first, each with its transport error class. With
// Responded() == 0 they are the explanation for an unreachable target. Fetches
// abandoned because the phase was cancelled are not included.
func (e *Executor) BaselineFailures() []BaselineFailure {
	return e.baselineFailures.snapshot()
}
