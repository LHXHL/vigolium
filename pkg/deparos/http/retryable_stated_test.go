package http

import (
	"context"
	"fmt"
	"testing"
)

type statedErr struct {
	retry bool
	cause error
}

func (e statedErr) Error() string   { return "stated" }
func (e statedErr) Unwrap() error   { return e.cause }
func (e statedErr) Retryable() bool { return e.retry }

// An error that states its own retryability wins over the net.Error shape of its
// cause: an egress gate refusing a request after a slot wait timed out wraps
// context.DeadlineExceeded, which is a net.Error, yet nothing was sent.
func TestIsRetryableHonoursStatedRetryability(t *testing.T) {
	refused := fmt.Errorf("wrapped: %w", statedErr{retry: false, cause: context.DeadlineExceeded})
	if IsRetryable(refused) {
		t.Fatal("a refusal that says it is not retryable was retried")
	}
	if IsRetryable(&RequestError{URL: "http://x/", Err: refused}) {
		t.Fatal("RequestError wrapping must not hide the stated retryability")
	}
	if !IsRetryable(statedErr{retry: true}) {
		t.Fatal("a stated-retryable error must be retried")
	}
}
