package stream

import (
	"errors"
	"strings"
)

// TransientErrSubstrings matches provider stream/HTTP errors that are
// worth a retry rather than a terminal fail. Sourced from observed
// golang.org/x/net/http2 + net/http error message shapes when an
// upstream server kills the stream mid-response (INTERNAL_ERROR,
// REFUSED_STREAM, GOAWAY) or a network blip drops the connection.
//
// Owned by pkg/olium/stream as the leaf so both pkg/olium/engine
// (in-flight retry around streamOnce) and pkg/agent/retry
// (cross-call retry around runOliumPrompt) read the same list.
var TransientErrSubstrings = []string{
	"connection refused", "connection reset", "broken pipe",
	"i/o timeout", "tls handshake", "no such host",
	"unexpected eof", "use of closed network connection",
	"stream error", "internal_error", "refused_stream",
	"enhance_your_calm", "goaway", "http2:",
}

// IsTransientErr reports whether err's message matches any pattern in
// TransientErrSubstrings (case-insensitive substring).
func IsTransientErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrStreamIncomplete) || IsRetryableStatusErr(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range TransientErrSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

// ErrStreamIncomplete reports a provider stream that ended without its
// terminal event. Treated as transient: the turn is incomplete, and
// committing it would silently record a truncated assistant message as if
// the model had finished speaking.
var ErrStreamIncomplete = errors.New("provider stream ended without a terminal event (unexpected eof)")

// contextOverflowSubstrings match the provider errors raised when the
// conversation no longer fits the model's context window. These are 400s -
// never retryable - but they are a budget condition rather than a failure,
// so callers should stop cleanly and report rather than die.
var contextOverflowSubstrings = []string{
	"context_length_exceeded", "prompt is too long",
	"maximum context length", "context window",
	"too many total text bytes", "input is too long",
	"reduce the length of the messages",
	// llama.cpp / LM Studio wordings
	"exceeds the available context size", "exceed_context_size",
	"context length of only",
}

// IsContextOverflow reports whether a provider error message says the
// request no longer fits the model's context window. Takes the message
// rather than an error because its callers classify an Event.Err string.
func IsContextOverflow(msg string) bool {
	msg = strings.ToLower(msg)
	for _, sub := range contextOverflowSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}
