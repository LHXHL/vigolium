package node2shell

import (
	nethttp "net/http"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

const (
	// UnknownEncoding is the control encoding. A server that drops or ignores
	// the body of any encoded request answers it like the decoded Brotli probe.
	UnknownEncoding = "x-vigolium"
	// DecoyHeader is a header no server reads. It carries a random value to show
	// odd headers alone do not move the answer, and the encoding name to show
	// decoding is tied to Content-Encoding rather than to any header.
	DecoyHeader = "X-Vigolium-Encoding"
	// ConfirmRounds is how many times the encoded pair must be answered like the
	// plain pair before the gate opens.
	ConfirmRounds = 2
	// ContentEncoding is the header the gate varies.
	ContentEncoding = "Content-Encoding"
)

// Exchange is one sent probe's outcome. Request and Response are evidence
// strings the caller has already truncated or elided as it sees fit.
type Exchange struct {
	Sig      modkit.ResponseSignature
	Header   nethttp.Header
	Request  string
	Response string
}

// SendFunc fires one probe: the caller's base request with body as its body and
// one extra header (none when value is empty). It reports false when the
// exchange could not be completed, which aborts the gate.
type SendFunc func(headerName, headerValue string, body []byte) (Exchange, bool)

// Gate is a completed decode differential: the two plain response classes the
// path answers with, and the encoded probes that proved the answer follows the
// decoded content rather than the header.
type Gate struct {
	// Bodies are the control streams that were decoded, so a caller that runs
	// a further stage can re-send the same valid control afterwards. Their
	// Encoding is the coding the path decoded — see Gate.Encoding.
	Bodies EncodedBodies
	// Empty and Malformed are the plain {} and plain { response classes.
	Empty, Malformed Exchange
	// Decoded and DecodedMalformed are the encoded {} and { answered like them.
	Decoded, DecodedMalformed Exchange
	// Unknown, Noise and Misplaced are the three controls that must NOT be
	// answered like the route's {} class (Noise must be).
	Unknown, Noise, Misplaced Exchange
	// Failed is the decode-failure class: what the path answers for bytes the
	// decoder itself refuses, as opposed to bytes it decodes into malformed
	// JSON. See BadStream.
	Failed Exchange
}

// RunGate runs the differential over every known encoding. See RunGateFor.
func RunGate(send SendFunc) (Gate, bool) { return RunGateFor(send, Encodings) }

// RunGateFor runs the decode differential against one method+path. It opens only
// when the answer follows the decoded content, not the header:
//
//   - the path reads its body: plain {} and plain { are answered differently,
//     and plain {} is not a 5xx or 429 (an erroring or throttled baseline
//     matches anything);
//   - encoded {} is answered like plain {} and encoded { like plain {, for
//     ConfirmRounds rounds. A server that reacts to the header alone (a WAF
//     block, a 4xx/5xx with odd headers, a dropped body) answers both encoded
//     bodies alike, and a flaky one breaks on the repeat;
//   - the same bytes under an unknown encoding are not answered like plain {};
//   - header decoys: plain {} with a random DecoyHeader is answered like plain
//     {}, and the encoded bytes with DecoyHeader naming the encoding (no
//     Content-Encoding) are not;
//   - a stream the decoder refuses outright is not answered like plain {}
//     either, which is what makes the decode-failure class observable.
//
// A server that ignores Content-Encoding sees the Brotli bytes as malformed
// JSON and stops at the first encoded probe.
//
// Ten round-trips on the happy path, all with bodies under 32 bytes. It is the
// precondition for the node2shell probe, which costs tens of MiB: spending ten
// tiny requests to learn there is no decoder here is what makes that
// affordable.
//
// candidates are the encodings to try, in order. A caller whose follow-up stage
// only works under one of them passes just that one rather than opening a gate
// it cannot use — see BrotliOnly.
func RunGateFor(send SendFunc, candidates []EncodedBodies) (Gate, bool) {
	empty, ok := send(ContentEncoding, "", EmptyJSON)
	if !ok || Unreliable(empty) {
		return Gate{}, false
	}
	malformed, ok := send(ContentEncoding, "", MalformedJSON)
	if !ok || Same(empty, malformed) {
		return Gate{}, false
	}

	g := Gate{Empty: empty, Malformed: malformed}
	var enc EncodedBodies
	for _, e := range candidates {
		d, ok := send(ContentEncoding, e.Encoding, e.Empty)
		if !ok {
			return Gate{}, false
		}
		if Same(d, empty) {
			enc, g.Decoded = e, d
			break
		}
		// Brotli bytes parsed as malformed JSON: nothing decodes br here, so a
		// stacked encoding will not decode either.
		if Same(d, malformed) {
			return Gate{}, false
		}
	}
	if enc.Encoding == "" {
		return Gate{}, false
	}
	g.Bodies = enc

	for round := range ConfirmRounds {
		if round > 0 {
			if d, ok := send(ContentEncoding, enc.Encoding, enc.Empty); !ok || !Same(d, empty) {
				return Gate{}, false
			}
		}
		if g.DecodedMalformed, ok = send(ContentEncoding, enc.Encoding, enc.Malformed); !ok || !Same(g.DecodedMalformed, malformed) {
			return Gate{}, false
		}
	}

	if g.Unknown, ok = send(ContentEncoding, UnknownEncoding, enc.Empty); !ok || Same(g.Unknown, empty) {
		return Gate{}, false
	}
	// Header decoys. An odd header alone must not move the answer, or the
	// unknown-encoding control differing proves nothing about Content-Encoding.
	// And the encoded bytes under a header that merely names br must not be
	// decoded: the decoded answer belongs to Content-Encoding itself.
	if g.Noise, ok = send(DecoyHeader, modkit.RandomAlnum(12), EmptyJSON); !ok || !Same(g.Noise, empty) {
		return Gate{}, false
	}
	if g.Misplaced, ok = send(DecoyHeader, enc.Encoding, enc.Empty); !ok || Same(g.Misplaced, empty) {
		return Gate{}, false
	}
	// Learn the decode-failure class last. A path that answers a stream the
	// decoder rejects exactly as it answers a valid one is not running a
	// decoder whose outcome anyone can observe.
	if g.Failed, ok = send(ContentEncoding, enc.Encoding, BadStream); !ok || Same(g.Failed, empty) {
		return Gate{}, false
	}
	return g, true
}

// Reverify re-sends the three tiny bodies the gate learned its classes from and
// reports whether all three still land where they did.
//
// A gate's classes are a snapshot. Anything that runs a further stage against
// them — the node2shell probe takes tens of MiB and several seconds — is
// scoring that stage against a picture of the endpoint taken earlier, and the
// picture goes stale in exactly the cases that produce a wrong answer: a load
// balancer rotating to a backend that never decoded, a worker restarting into a
// different configuration, a route whose answer depends on state the earlier
// probes themselves changed.
//
// Three sub-32-byte requests, so a caller can afford to run it between every
// expensive round rather than once at the end.
func Reverify(send SendFunc, g Gate) bool {
	for _, c := range []struct {
		body []byte
		want Exchange
	}{
		{g.Bodies.Empty, g.Empty},
		{g.Bodies.Malformed, g.Malformed},
		{BadStream, g.Failed},
	} {
		got, ok := send(ContentEncoding, g.Encoding(), c.body)
		if !ok || !Same(got, c.want) {
			return false
		}
	}
	return true
}

// Encoding is the Content-Encoding the path decoded (BrotliEncoding, or
// StackedEncoding when a guard refused plain br). It is derived from Bodies
// rather than stored, so a Gate cannot describe one coding and carry the
// control streams of another.
func (g Gate) Encoding() string { return g.Bodies.Encoding }

// Same reports whether two answers are the same page: equal status and a
// similar body.
func Same(a, b Exchange) bool { return modkit.RatioSimilar(a.Sig, b.Sig) }

// Unreliable reports a baseline that cannot anchor the differential: a server
// error or a throttle answers every probe alike.
func Unreliable(e Exchange) bool {
	return e.Sig.StatusCode >= 500 || e.Sig.StatusCode == nethttp.StatusTooManyRequests
}
