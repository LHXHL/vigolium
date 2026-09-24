package stream

import (
	"errors"
	"fmt"
	"testing"
)

// TestRetryableStatusIsTransient is the integration point: a retryable
// status must also read as transient, since that is what actually drives
// the engine's retry.
func TestRetryableStatusIsTransient(t *testing.T) {
	if !IsTransientErr(fmt.Errorf("anthropic 529: overloaded")) {
		t.Error("a 529 must be transient")
	}
	if IsTransientErr(errors.New("anthropic 400: bad request")) {
		t.Error("a 400 must not be transient")
	}
}

func TestIsContextOverflow(t *testing.T) {
	if !IsContextOverflow("anthropic 400: prompt is too long: 213000 tokens > 200000 maximum") {
		t.Error("anthropic overflow not recognized")
	}
	if !IsContextOverflow("openai 400: context_length_exceeded") {
		t.Error("openai overflow not recognized")
	}
	if IsContextOverflow("anthropic 400: invalid tool name") {
		t.Error("unrelated 400 misread as overflow")
	}
}
