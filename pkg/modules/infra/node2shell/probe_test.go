package node2shell

import (
	"bytes"
	"io"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestStreamSizes pins the two Content-Lengths the oracle depends on. The
// probe's size is not a round number and not adjustable: it is prefix + 2^21-1
// units + suffix, and a decoder only reaches the wrap at exactly that count.
func TestStreamSizes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 23068764, ProbeBytes)
	assert.Equal(t, 23068775, TwinBytes)
	assert.Equal(t, ProbeBytes+len(probeUnit), TwinBytes, "the twin is exactly one unit longer")

	probe := ProbeStream()
	require.Len(t, probe, ProbeBytes)
	assert.True(t, bytes.HasPrefix(probe, probePrefix))
	assert.True(t, bytes.HasSuffix(probe, probeSuffix))

	twin := TwinStream()
	require.Len(t, twin, TwinBytes)
	assert.True(t, bytes.HasSuffix(twin, probeSuffix))
	// The two differ only in the repeat count, which is the point: the twin is
	// the same shape and size class, so anything that reacts to those rather
	// than to the decode answers both alike.
	assert.Equal(t, probe[:len(probePrefix)+len(probeUnit)], twin[:len(probePrefix)+len(probeUnit)])
	assert.NotEqual(t, len(probe), len(twin))
}

// TestProbeUnitCount walks the repeated region and asserts it is units all the
// way down — a stray byte anywhere in 22 MiB would silently destroy the oracle
// while leaving the length right.
func TestProbeUnitCount(t *testing.T) {
	t.Parallel()

	probe := ProbeStream()
	body := probe[len(probePrefix) : len(probe)-len(probeSuffix)]
	require.Zero(t, len(body)%len(probeUnit))
	assert.Equal(t, ProbeReps, len(body)/len(probeUnit))
	for off := 0; off < len(body); off += len(probeUnit) {
		if !bytes.Equal(body[off:off+len(probeUnit)], probeUnit) {
			t.Fatalf("probe diverges from the repeated unit at offset %d", off)
		}
	}
}

// TestGoDecoderRejectsBothStreams documents that the Go Brotli port carries a
// correct block-switch limit and refuses the probe as well as the twin.
//
// This is why the module's tests simulate an affected decoder instead of
// running one: nothing in this repo's dependency tree can decode the probe, and
// that is the right outcome — vigolium itself is not exposed to the bug it
// probes for.
func TestGoDecoderRejectsBothStreams(t *testing.T) {
	t.Parallel()

	for name, stream := range map[string][]byte{"probe": ProbeStream(), "twin": TwinStream()} {
		_, err := io.ReadAll(brotli.NewReader(bytes.NewReader(stream)))
		assert.Error(t, err, "%s: the Go decoder is not affected and must refuse it", name)
	}
}

// TestDecodedProbeIsValidJSONObject pins what an affected decoder emits: the
// controls must stand for the same document, or the oracle compares the probe
// against the wrong response class.
func TestDecodedProbeIsValidJSONObject(t *testing.T) {
	t.Parallel()

	assert.Len(t, DecodedProbe, 66)
	assert.Equal(t, "{}", string(bytes.TrimSpace(DecodedProbe)))
	assert.Equal(t, EmptyJSON, bytes.TrimSpace(DecodedProbe),
		"the valid control must decode to the same document as the probe")
}

// Plain br must come first: a server that takes it must never be probed with
// the stacked form, and BrotliOnly selects on the coding rather than on an
// index.
func TestEncodingsPreferPlainBrotli(t *testing.T) {
	t.Parallel()

	require.NotEmpty(t, Encodings)
	assert.Equal(t, BrotliEncoding, Encodings[0].Encoding)
	assert.Equal(t, StackedEncoding, Encodings[1].Encoding)
}

// TestEncodedControlsRoundTrip decodes the precomputed control streams back:
// the differential is meaningless if they do not carry {} and {.
func TestEncodedControlsRoundTrip(t *testing.T) {
	t.Parallel()

	for _, e := range Encodings {
		out, ok := modtest.DecodeContentEncoding(e.Empty, e.Encoding, nil)
		require.True(t, ok, e.Encoding)
		assert.Equal(t, EmptyJSON, out, e.Encoding)

		out, ok = modtest.DecodeContentEncoding(e.Malformed, e.Encoding, nil)
		require.True(t, ok, e.Encoding)
		assert.Equal(t, MalformedJSON, out, e.Encoding)
	}
}
