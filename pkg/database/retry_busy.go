package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"go.uber.org/zap"
)

// RetryPolicy bounds RetryBusy. The zero value is usable: every unset field
// falls back to DefaultRetryPolicy's.
type RetryPolicy struct {
	// Op names the operation in debug logs and in the final error.
	Op string
	// MaxAttempts is the total number of calls to fn, including the first.
	MaxAttempts int
	// BaseDelay is the wait after the first failure; it doubles per attempt up
	// to MaxDelay.
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// Retryable decides whether an error is worth another attempt. Nil means
	// IsBusy: only SQLite busy/locked errors are retried, anything else returns
	// at once.
	Retryable func(error) bool
	// Wait sleeps between attempts. Nil means a context-aware timer. A caller
	// that holds a mutex across fn supplies one that releases it while waiting.
	Wait func(ctx context.Context, d time.Duration) error
}

// DefaultRetryPolicy is the budget the merge path has always used: 12 attempts,
// 50ms doubling to 2s, about 14s in total. Long enough to ride out another
// process's write transaction, short enough that a wedged store surfaces.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts: 12,
	BaseDelay:   50 * time.Millisecond,
	MaxDelay:    2 * time.Second,
}

// ErrDatabaseLocked is the sentinel every exhausted busy retry unwraps to.
var ErrDatabaseLocked = errors.New("database is locked by another writer")

// LockedError reports a busy retry budget that ran out. It carries the stable
// code database_locked, so the CLI's error document and a REST body name the
// condition the same way, and it unwraps to both ErrDatabaseLocked and the last
// driver error.
type LockedError struct {
	Op       string
	Attempts int
	Err      error
}

func (e *LockedError) Error() string {
	op := e.Op
	if op == "" {
		op = "database operation"
	}
	return fmt.Sprintf("%s gave up after %d attempts: %v (another vigolium process is writing; retry when it finishes)",
		op, e.Attempts, e.Err)
}

// Unwrap exposes both the sentinel and the driver error.
func (e *LockedError) Unwrap() []error { return []error{ErrDatabaseLocked, e.Err} }

// Code is the stable error code (database_locked).
func (e *LockedError) Code() apicontract.ErrorCode { return apicontract.CodeDatabaseLocked }

// IsBusy reports whether err is a transient SQLite busy/locked error, the kind
// another connection's write transaction produces once busy_timeout runs out.
// Matched on text because the driver wraps them as plain errors; SQLite's own
// messages and result codes are fixed in its source, not localized.
func IsBusy(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrDatabaseLocked) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "(5)") || // SQLITE_BUSY
		strings.Contains(msg, "(6)") // SQLITE_LOCKED
}

// RetryBusy runs fn, retrying with exponential backoff while policy.Retryable
// accepts the error. It returns nil on the first success and the error itself
// on the first non-retryable failure. When the budget runs out on a busy error
// the result is a *LockedError (code database_locked); when it runs out on any
// other retryable error, that error is returned unchanged. A cancelled ctx stops
// the wait and returns ctx.Err().
func RetryBusy(ctx context.Context, fn func() error, policy RetryPolicy) error {
	p := policy.withDefaults()
	delay := p.BaseDelay
	var lastErr error
	for attempt := 1; attempt <= p.MaxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil || !p.Retryable(lastErr) {
			return lastErr
		}
		if attempt == p.MaxAttempts {
			break
		}
		zap.L().Debug("database busy, retrying",
			zap.String("op", p.Op), zap.Int("attempt", attempt),
			zap.Duration("delay", delay), zap.Error(lastErr))
		if err := p.Wait(ctx, delay); err != nil {
			return err
		}
		delay = min(delay*2, p.MaxDelay)
	}
	if IsBusy(lastErr) {
		return &LockedError{Op: p.Op, Attempts: p.MaxAttempts, Err: lastErr}
	}
	return lastErr
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultRetryPolicy.MaxAttempts
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = DefaultRetryPolicy.BaseDelay
	}
	if p.MaxDelay < p.BaseDelay {
		p.MaxDelay = max(DefaultRetryPolicy.MaxDelay, p.BaseDelay)
	}
	if p.Retryable == nil {
		p.Retryable = IsBusy
	}
	if p.Wait == nil {
		p.Wait = sleepCtx
	}
	return p
}

// sleepCtx waits d or until ctx is done, whichever is first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
