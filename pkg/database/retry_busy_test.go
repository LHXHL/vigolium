package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

func TestRetryBusy_BackoffAndExhaustion(t *testing.T) {
	var waits []time.Duration
	policy := RetryPolicy{
		Op:          "unit",
		MaxAttempts: 5,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    30 * time.Millisecond,
		Wait: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		},
	}
	calls := 0
	busy := errors.New("database is locked (5) (SQLITE_BUSY)")
	err := RetryBusy(context.Background(), func() error { calls++; return busy }, policy)

	if calls != 5 {
		t.Fatalf("calls = %d, want 5", calls)
	}
	want := []time.Duration{10, 20, 30, 30}
	for i := range want {
		want[i] *= time.Millisecond
	}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v (no wait after the last attempt)", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}

	var locked *LockedError
	if !errors.As(err, &locked) || locked.Attempts != 5 {
		t.Fatalf("err = %v, want *LockedError after 5 attempts", err)
	}
	if !errors.Is(err, ErrDatabaseLocked) || !errors.Is(err, busy) {
		t.Errorf("LockedError must unwrap to ErrDatabaseLocked and the driver error: %v", err)
	}
	if locked.Code() != apicontract.CodeDatabaseLocked {
		t.Errorf("code = %q, want database_locked", locked.Code())
	}
}

func TestRetryBusy_SucceedsAndStopsOnOtherErrors(t *testing.T) {
	noWait := RetryPolicy{Wait: func(context.Context, time.Duration) error { return nil }}

	calls := 0
	if err := RetryBusy(context.Background(), func() error {
		calls++
		if calls < 3 {
			return errors.New("database is locked")
		}
		return nil
	}, noWait); err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want success on the third call", err, calls)
	}

	calls = 0
	boom := errors.New("boom")
	if err := RetryBusy(context.Background(), func() error { calls++; return boom }, noWait); err != boom || calls != 1 { //nolint:errorlint // must be boom itself, not a wrapper
		t.Fatalf("err=%v calls=%d, want boom after one call", err, calls)
	}

	// A custom predicate that retries everything returns the last error itself
	// (not a LockedError) when it is not a busy error.
	calls = 0
	retryAll := noWait
	retryAll.MaxAttempts = 3
	retryAll.Retryable = func(error) bool { return true }
	if err := RetryBusy(context.Background(), func() error { calls++; return boom }, retryAll); err != boom || calls != 3 { //nolint:errorlint // must be boom itself, not a LockedError wrapping it
		t.Fatalf("err=%v calls=%d, want boom after three calls", err, calls)
	}
}

func TestRetryBusy_ContextCancelStopsWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RetryBusy(ctx, func() error { return errors.New("database is locked") },
		RetryPolicy{BaseDelay: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
