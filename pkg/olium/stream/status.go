package stream

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// StatusError is a provider's non-200 HTTP response, carried as a typed
// error so callers can act on the status instead of parsing it back out of a
// string. Every driver built the same "<provider> <status>: <body>" text and
// threw the int away; the retry classifiers then recovered it by pattern
// matching, which made that format load-bearing - a single fmt.Errorf wrap
// would silently stop retries working.
//
// Error() keeps the original wording, so operator-facing output is unchanged.
type StatusError struct {
	// Provider names the driver ("anthropic", "openai-compatible", ...).
	Provider string
	// Status is the HTTP status code.
	Status int
	// Body is the response body, already trimmed to something printable.
	Body string
	// Hint is optional operator guidance appended after the body (e.g. how
	// to rotate an expired token on a 401).
	Hint string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("%s %d%s", e.Provider, e.Status, e.Hint)
	}
	return fmt.Sprintf("%s %d: %s%s", e.Provider, e.Status, e.Body, e.Hint)
}

// Retryable reports whether another attempt is worth making.
func (e *StatusError) Retryable() bool { return retryableStatuses[e.Status] }

// RateLimited reports whether the server asked us to slow down, as opposed
// to failing. Callers that pace themselves differently for the two cases
// (the cross-call retry layer) need to tell them apart.
func (e *StatusError) RateLimited() bool { return e.Status == 429 }

// StatusOf extracts a StatusError from err, unwrapping as needed, falling
// back to StatusOfText.
func StatusOf(err error) (*StatusError, bool) {
	if err == nil {
		return nil, false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se, true
	}
	return StatusOfText(err.Error())
}

// StatusOfText recovers a status from the formatted text Error() produces.
// It exists because engine events carry the provider error as a plain
// string (engine.Event.Err), so the typed value is lost in transit; parsing
// it back is a transition shim, and it can be deleted once Event carries the
// status itself.
//
// The status is the second whitespace-separated token, optionally
// colon-suffixed. Cut rather than Fields: the body may be a 64 KiB error
// page, and splitting it would allocate a slice per word and collapse the
// whitespace we then print back.
func StatusOfText(msg string) (*StatusError, bool) {
	provider, rest, ok := strings.Cut(msg, " ")
	if !ok {
		return nil, false
	}
	token, body, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(strings.TrimSuffix(token, ":"))
	if err != nil || code < 100 || code > 599 {
		return nil, false
	}
	return &StatusError{Provider: provider, Status: code, Body: body}, true
}

// NewStatusError builds a StatusError, trimming the body to something
// printable. Drivers call this at the one place they read a non-200.
func NewStatusError(provider string, status int, body []byte) *StatusError {
	return &StatusError{Provider: provider, Status: status, Body: strings.TrimSpace(string(body))}
}

// WithHint returns a copy carrying operator guidance, appended verbatim
// after the body - so the caller owns any leading separator.
func (e *StatusError) WithHint(hint string) *StatusError {
	clone := *e
	clone.Hint = hint
	return &clone
}

// retryableStatuses are the HTTP statuses worth another attempt: the server
// is busy, overloaded, or briefly broken. Deliberately excludes 4xx that
// describe the request itself (400/401/403/404/413/422) - retrying those
// just burns the budget and delays the real error.
//
//	408 request timeout · 425 too early · 429 rate limited
//	500/502/503/504 server-side · 520-524 Cloudflare edge
//	529 anthropic overloaded_error
//
// One table, read by both the engine's in-flight stream retry and the
// cross-call retry in pkg/agent - they used to keep separate lists that had
// already drifted (a Cloudflare 520 retried at one layer only).
var retryableStatuses = map[int]bool{
	408: true, 425: true, 429: true,
	500: true, 502: true, 503: true, 504: true,
	520: true, 521: true, 522: true, 524: true,
	529: true,
}

// IsRetryableStatusErr reports whether err carries a provider HTTP status
// worth retrying. A single 429, or one Anthropic 529 overload, used to kill
// an entire multi-hour agent run on the first occurrence.
func IsRetryableStatusErr(err error) bool {
	se, ok := StatusOf(err)
	return ok && se.Retryable()
}
