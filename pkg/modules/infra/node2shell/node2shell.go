// Package node2shell holds what the Brotli request-decoding exposure probe and
// the node2shell decoder-version probe share about CVE-2026-111497: the tiny
// Brotli control streams both send, the advisory references, and the heuristic
// that names the component which probably decoded the body.
//
// The two modules ask different halves of one question. The exposure probe asks
// whether anything on the request path decodes a Brotli request body at all —
// surface, no version. The node2shell probe asks whether that decoder predates
// the fix, and pays 22 MiB of upload to find out. They must agree on where the
// decoder is, so the differential's streams live here rather than in either
// module.
package node2shell

import (
	nethttp "net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// CVE is the identifier the advisory assigns to the Brotli decoder bug.
const CVE = "CVE-2026-111497"

const (
	// BrotliEncoding is the plain Brotli coding, and the only one the
	// node2shell probe can be delivered under. Declared once here so the
	// string is not spelled independently by Encodings, BrotliOnly and the
	// module that checks it.
	BrotliEncoding = "br"
	// StackedEncoding is tried when plain br is refused: a guard that checks
	// only the first token lets it through to a decoder that handles both.
	StackedEncoding = "gzip, " + BrotliEncoding
)

// FixedReleases names the first patched build of each affected decoder.
const FixedReleases = "Node.js 22.23.4/24.22.1/26.12.1, Bun 1.4.4, Envoy 1.37.8+, Istio 1.29.9+, libbrotli 1.0.10/1.1.1/1.2.1"

// References are attached to every CVE-2026-111497 result. The Assetnote
// scanner is the source of the 22 MiB probe stream the node2shell module sends.
var References = []string{
	"https://patchtheplanet.org/brotli",
	"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
	"https://istio.io/latest/news/security/istio-security-2026-007/",
	"https://github.com/google/brotli/releases/tag/v1.2.1",
	"https://github.com/assetnote/node2shell-scanner",
}

var (
	// EmptyJSON is valid JSON a handler can only refuse or accept as empty;
	// MalformedJSON is what every JSON parser refuses. A route that answers both
	// the same does not read its body and carries no signal.
	//
	// EmptyJSON is "{}" rather than the empty string on purpose: the 22 MiB probe
	// decodes to "{}" followed by spaces, so the control that stands for "the
	// decode succeeded" must decode to the same document. The Assetnote scanner's
	// valid control is a one-byte stream that decodes to "", which an app that
	// refuses an empty body but accepts {} puts in the MALFORMED class — on a
	// genuinely vulnerable target that reads as no signal.
	EmptyJSON     = []byte("{}")
	MalformedJSON = []byte("{")

	// BadStream is one byte that is not a valid Brotli document (and not a
	// valid gzip one either, so it fails under StackedEncoding too). Sent under
	// the encoding the gate proved is decoded, it learns a THIRD response class:
	// what the path answers when the decode itself fails, as opposed to when it
	// succeeds and the JSON parser then refuses the result.
	//
	// Servers distinguish the two — "Decompression failed" is not "Unexpected
	// end of JSON input" — and the node2shell probe needs the distinction: its
	// size-matched twin is a stream no decoder accepts, so it belongs in this
	// class, not in the malformed-JSON one.
	BadStream = []byte{0xff}
)

// EncodedBodies is one Content-Encoding with EmptyJSON and MalformedJSON
// encoded under it.
type EncodedBodies struct {
	Encoding         string
	Empty, Malformed []byte
}

// BrotliOnly restricts a gate to plain br.
//
// The node2shell probe needs it. Its stream is a bare Brotli document whose
// output is fixed at 66 bytes of JSON by the construction that drives the
// counter to the wrap — so under "gzip, br" a server un-brs it to those 66
// bytes and then tries to gunzip them, which fails on every build, affected or
// not. There is no stacked form of the probe to send, and a gate that opened on
// StackedEncoding would hand the version stage 22 MiB that can only come back
// negative. Such a host is still real exposure; it is just not testable this
// way, and the exposure module reports it.
func BrotliOnly() []EncodedBodies { return encodingsFor(BrotliEncoding) }

// encodingsFor selects the Encodings entries with the given coding, so a
// restricted gate is derived from the table rather than from a hardcoded index
// that silently selects the wrong row if the table is reordered.
func encodingsFor(coding string) []EncodedBodies {
	var out []EncodedBodies
	for _, e := range Encodings {
		if e.Encoding == coding {
			out = append(out, e)
		}
	}
	return out
}

// Encodings are EmptyJSON and MalformedJSON encoded as br and as "gzip, br"
// (gzip applied first), precomputed so no encoder runs at startup
// (TestEncodedControlsRoundTrip decodes them back). Tiny well-formed streams:
// ordinary decoder use, nowhere near the CVE-2026-111497 trigger.
var Encodings = []EncodedBodies{
	{
		Encoding:  BrotliEncoding,
		Empty:     []byte{0x8b, 0x00, 0x80, 0x7b, 0x7d, 0x03},
		Malformed: []byte{0x0b, 0x00, 0x80, 0x7b, 0x03},
	},
	{
		Encoding: StackedEncoding,
		Empty: []byte{
			0x0b, 0x0d, 0x80, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x02, 0x00,
			0xfd, 0xff, 0x7b, 0x7d, 0x03, 0x00, 0x43, 0xbf, 0xa6, 0xa3, 0x02, 0x00, 0x00, 0x00, 0x03,
		},
		Malformed: []byte{
			0x8b, 0x0c, 0x80, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00,
			0xfe, 0xff, 0x7b, 0x03, 0x00, 0x39, 0x47, 0xd5, 0x15, 0x01, 0x00, 0x00, 0x00, 0x03,
		},
	},
}

// LikelyDecoder names the component that probably decoded the body. A proxy in
// the path is named first: it decodes before the app, and a Python or Go app
// behind it is exposed only through it. Envoy and Bun have no fingerprint tag,
// so their headers are read here; app stacks come from the tech registry. The
// label is a hint for the reader, never a gate.
func LikelyDecoder(scanCtx *modkit.ScanContext, host string, header nethttp.Header) string {
	server := strings.ToLower(header.Get("Server"))
	switch {
	case strings.Contains(server, "envoy") || header.Get("X-Envoy-Upstream-Service-Time") != "":
		return "Envoy/Istio proxy in path (the proxy's decompressor, or the app behind it)"
	case strings.Contains(server, "bun"):
		return "Bun"
	case scanCtx.HasAnyTech(host, []string{"express", "nestjs", "nextjs", "nodejs"}):
		return "Node.js app (body parser)"
	case scanCtx.HasAnyTech(host, []string{"python", "django", "flask", "fastapi"}):
		return "Python app (custom decoding middleware, or an unseen proxy in front)"
	}
	return "unidentified"
}
