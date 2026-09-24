package stream

import (
	"errors"
	"fmt"
	"testing"
)

func TestStatusErrorRoundTrip(t *testing.T) {
	se := NewStatusError("anthropic", 429, []byte(`{"type":"rate_limit_error"}`))
	if got, want := se.Error(), `anthropic 429: {"type":"rate_limit_error"}`; got != want {
		t.Errorf("Error() = %q, want %q (operator-facing wording must not change)", got, want)
	}
	if !se.Retryable() || !se.RateLimited() {
		t.Error("429 must be retryable and rate-limited")
	}

	// Survives wrapping - the whole point of the typed error. The old
	// regexp anchored at ^, so any wrap silently stopped retries working.
	wrapped := fmt.Errorf("stream failed: %w", se)
	got, ok := StatusOf(wrapped)
	if !ok || got.Status != 429 {
		t.Errorf("StatusOf(wrapped) = %+v, %v; want status 429", got, ok)
	}
	if !IsRetryableStatusErr(wrapped) {
		t.Error("a wrapped 429 must still read as retryable")
	}
}

func TestStatusOfTextFallback(t *testing.T) {
	// Errors that crossed a string boundary (an engine Event.Err) still
	// classify.
	cases := map[string]struct {
		status    int
		retryable bool
	}{
		"anthropic 529: overloaded_error":     {529, true},
		"openai-compatible 503":               {503, true},
		"google-vertex 500: internal":         {500, true},
		"openai-compatible 520: cloudflare":   {520, true},
		"anthropic 400: bad request":          {400, false},
		"openai 404: model 'x' not found":     {404, false},
		"anthropic 401: authentication_error": {401, false},
	}
	for msg, want := range cases {
		se, ok := StatusOfText(msg)
		if !ok {
			t.Errorf("StatusOfText(%q) did not parse", msg)
			continue
		}
		if se.Status != want.status {
			t.Errorf("StatusOfText(%q).Status = %d, want %d", msg, se.Status, want.status)
		}
		if se.Retryable() != want.retryable {
			t.Errorf("StatusOfText(%q).Retryable() = %v, want %v", msg, se.Retryable(), want.retryable)
		}
	}
	if _, ok := StatusOfText("connection refused"); ok {
		t.Error("a bare network error must not parse as a status")
	}
	if _, ok := StatusOfText("anthropic 99: nope"); ok {
		t.Error("an out-of-range code must not parse as a status")
	}
}

func TestStatusErrorHint(t *testing.T) {
	se := NewStatusError("anthropic", 401, []byte("authentication_error"))
	hinted := se.WithHint(" — rotate the key")
	if hinted.Error() != "anthropic 401: authentication_error — rotate the key" {
		t.Errorf("hint not appended: %q", hinted.Error())
	}
	if se.Hint != "" {
		t.Error("WithHint must not mutate the original")
	}
	var target *StatusError
	if !errors.As(error(hinted), &target) || target.Status != 401 {
		t.Error("a hinted error must still classify")
	}
}
