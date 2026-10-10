package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
)

// Phase-error policy. A phase error is one of three things, and executeNativePhase
// is the one place that tells them apart:
//
//   - fatal (errFatal): the infrastructure every later phase depends on is gone —
//     the database or a record store is closed or cannot be written, the output
//     writer is closed, a session was lost under reauth.on_failure: abort.
//     Continuing would run phases whose results can no longer be stored, so the
//     scan stops, the remaining phases are recorded as skipped, and the error is
//     returned: it is the scan row's error_message and scan.finished's message.
//   - curtailment: the phase stopped because the scan's own context did (Ctrl-C,
//     --scanning-max-duration, --max-requests, an auth abort). Not a failure of
//     the phase; its tracker marks it partial with the context's stop reason and
//     the phase loop records the phases that never started.
//   - everything else: a phase failure. The phase outcome is failed with reason
//     phase_error, an `error` event is emitted, and the scan carries on — the
//     later phases still have whatever the earlier ones stored. Discovery and
//     seed are no exception: a scan whose input never reached the database is
//     caught by the preflight's no_targets_in_scope / no_targets_reachable stop,
//     and a DA that then finds nothing to do says so on its own outcome.
//
// An explicit --auth-file login failure is fatal too, but it never reaches here:
// buildInfrastructure returns it before the first phase starts.

// errFatal is the sentinel every fatal phase error matches with errors.Is. Wrap
// an error with fatal() to mark it; isFatalPhaseError also recognises the known
// infrastructure failures without a wrapper, because they surface from deep
// inside phases that cannot know they are fatal.
var errFatal = errors.New("fatal scan infrastructure error")

// fatalError marks err as fatal while keeping its own message and chain, so
// error codes (AuthLostError.Code) and errors.As still see the cause.
type fatalError struct{ err error }

func (e *fatalError) Error() string        { return e.err.Error() }
func (e *fatalError) Unwrap() error        { return e.err }
func (e *fatalError) Is(target error) bool { return target == errFatal }

// fatal wraps err as fatal. nil stays nil, and an already-fatal error is
// returned unchanged.
func fatal(err error) error {
	if err == nil || errors.Is(err, errFatal) {
		return err
	}
	return &fatalError{err: err}
}

// errPhaseSkipped is returned by a phaseRunner.run that found nothing to do. It
// is not an error: the wrapper logs no "completed" line and runs no post-step.
var errPhaseSkipped = errors.New("phase skipped")

// unwritableStoreMarkers are the driver messages for a database that can no
// longer be written. Matched as text because database/sql's "database is
// closed" is unexported and the SQLite driver's codes arrive formatted.
var unwritableStoreMarkers = []string{
	"sql: database is closed",
	"database or disk is full",
	"attempt to write a readonly database",
}

// isFatalPhaseError reports whether a phase error means the scan cannot go on.
func isFatalPhaseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errFatal) {
		return true
	}
	var lost *AuthLostError
	if errors.As(err, &lost) {
		return true
	}
	if core.IsLevelDBClosed(err) ||
		errors.Is(err, database.ErrRecordWriterClosed) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, syscall.ENOSPC) ||
		errors.Is(err, syscall.EROFS) {
		return true
	}
	msg := err.Error()
	for _, marker := range unwritableStoreMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// stoppedByScanContext reports whether err is the phase reporting that the
// scan's context ended (cancellation, a scan budget, the request budget, an
// auth abort) rather than a failure of its own. ctx is the context the phase
// ran under; a live ctx means the error is the phase's own.
func stoppedByScanContext(ctx context.Context, err error) bool {
	if err == nil || ctx == nil || ctx.Err() == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var budget *egress.BudgetError
	var lost *AuthLostError
	return errors.As(err, &budget) || errors.As(err, &lost)
}
