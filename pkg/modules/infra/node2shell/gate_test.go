package node2shell

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// reply builds an Exchange with a given status and body, the way a real send
// would.
func reply(status int, body string) Exchange {
	return Exchange{Sig: modkit.NewResponseSignature(status, body, "")}
}

// classifier answers a body the way a JSON route behind a working Brotli
// decoder does, so a gate can be driven without a server.
func classifier(affected bool) SendFunc {
	return func(name, value string, body []byte) (Exchange, bool) {
		if name != ContentEncoding || value == "" {
			// No Content-Encoding (or a decoy header): the bytes arrive raw.
			return jsonAnswer(body), true
		}
		if value != "br" && value != StackedEncoding {
			return reply(415, `unsupported content encoding`), true
		}
		if bytes.Equal(body, BadStream) {
			return reply(400, `Error: Decompression failed`), true
		}
		switch {
		case bytes.Equal(body, Encodings[0].Empty), bytes.Equal(body, Encodings[1].Empty):
			return jsonAnswer(EmptyJSON), true
		case bytes.Equal(body, Encodings[0].Malformed), bytes.Equal(body, Encodings[1].Malformed):
			return jsonAnswer(MalformedJSON), true
		}
		if affected && len(body) == ProbeBytes {
			return jsonAnswer(DecodedProbe), true
		}
		return reply(400, `Error: Decompression failed`), true
	}
}

func jsonAnswer(body []byte) Exchange {
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{}")) {
		return reply(400, `{"error":"invalid JSON"}`)
	}
	return reply(422, `{"error":"field name is required"}`)
}

// A gate over a working decoder learns three distinct classes.
func TestRunGate_LearnsThreeClasses(t *testing.T) {
	t.Parallel()

	g, ok := RunGate(classifier(false))
	require.True(t, ok)
	assert.Equal(t, BrotliEncoding, g.Encoding())
	assert.False(t, Same(g.Empty, g.Malformed), "{} and { must be distinguishable")
	assert.False(t, Same(g.Empty, g.Failed), "a decode failure must not read like a success")
	assert.False(t, Same(g.Empty, g.Unknown))
	assert.True(t, Same(g.Noise, g.Empty), "an odd header alone must not move the answer")
}

// RunGateFor restricted to br never sends the stacked control, so a gate that
// only the stacked form would open stays closed.
func TestRunGateFor_BrotliOnlyDoesNotTryStacked(t *testing.T) {
	t.Parallel()

	var tried []string
	base := classifier(false)
	send := func(name, value string, body []byte) (Exchange, bool) {
		if name == ContentEncoding && value != "" {
			tried = append(tried, value)
		}
		return base(name, value, body)
	}

	_, ok := RunGateFor(send, BrotliOnly())
	require.True(t, ok)
	assert.NotContains(t, tried, StackedEncoding)
	require.Len(t, BrotliOnly(), 1)
	assert.Equal(t, BrotliEncoding, BrotliOnly()[0].Encoding)
}

// A path that answers a refused stream exactly as it answers a valid one has
// no observable decode outcome, so the gate stays closed.
func TestRunGate_ClosedWhenDecodeFailureIsInvisible(t *testing.T) {
	t.Parallel()

	base := classifier(false)
	send := func(name, value string, body []byte) (Exchange, bool) {
		if bytes.Equal(body, BadStream) {
			return jsonAnswer(EmptyJSON), true // a refused stream reads like {}
		}
		return base(name, value, body)
	}

	_, ok := RunGate(send)
	assert.False(t, ok)
}

func TestReverify(t *testing.T) {
	t.Parallel()

	g, ok := RunGate(classifier(false))
	require.True(t, ok)
	assert.True(t, Reverify(classifier(false), g), "an unchanged endpoint re-proves its classes")

	// Every tiny body now gets one page: the three classes have collapsed.
	collapsed := func(name, value string, body []byte) (Exchange, bool) {
		return reply(200, `{"status":"degraded"}`), true
	}
	assert.False(t, Reverify(collapsed, g))

	// A transport failure is not a re-proof either.
	broken := func(name, value string, body []byte) (Exchange, bool) { return Exchange{}, false }
	assert.False(t, Reverify(broken, g))
}
