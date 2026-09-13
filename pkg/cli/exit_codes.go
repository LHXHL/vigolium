package cli

import (
	"errors"
	"fmt"
)

// Process exit codes.
//
// `1` used to mean both "the scan crashed" and "the scan worked and found a
// high-severity finding" — opposite outcomes that a CI job or an agent has to
// react to differently, and could not tell apart. Splitting them is the whole
// change; the rest of the table is written down so a consumer can rely on it.
//
//	0  success
//	1  error
//	2  usage error (bad flag, bad combination)
//	3  fuzz --fail-on-match matched
//	4  --fail-on <severity> gate tripped
//
// --soft-fail still forces 0 everywhere, unchanged: a caller that has opted out
// of exit-code gating opted out of all of it.
const (
	ExitSuccess    = 0
	ExitError      = 1
	ExitUsageError = 2
	ExitFuzzMatch  = 3
	ExitFailOnGate = 4
)

// usageError marks an error as a misuse of the command line — an unknown flag
// value, a rejected combination, a missing required flag — rather than a
// failure of the work. Cobra's own flag-parse errors are classified separately
// (see classifyExitCode), because they never pass through here.
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }
func (u usageError) Unwrap() error { return u.err }

// asUsageError wraps err so Execute exits 2. Returns nil for a nil error, so it
// can wrap a call site's return value directly.
func asUsageError(err error) error {
	if err == nil {
		return nil
	}
	return usageError{err: err}
}

// usageErrorf builds a usage error (exit 2) from a format string, for the common
// case of rejecting a bad flag value at its own call site.
func usageErrorf(format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...)}
}

// gateError marks the --fail-on severity gate. It is not a failure: the scan ran
// to completion and its output was written before this is returned. A consumer
// distinguishing "found something" from "broke" reads exit 4 vs exit 1.
type gateError struct{ err error }

func (g gateError) Error() string { return g.err.Error() }
func (g gateError) Unwrap() error { return g.err }

// matchError marks a --fail-on-match / --fail-on-crack hit. Like gateError it is
// a completed result, not a failure: the work ran, its output was written, and
// the caller asked to learn about a match through the exit status.
//
// It exists because the three utilities that report a match used to call
// os.Exit(ExitFuzzMatch) directly from their handler. os.Exit runs no deferred
// functions, so that skipped the database close, the temporary-file cleanup, and
// the log flush; it also jumped over Execute entirely, so --soft-fail — which is
// documented as forcing a successful exit everywhere — silently did not apply to
// the one exit code an operator is most likely to want suppressed in CI.
type matchError struct{ err error }

func (m matchError) Error() string { return m.err.Error() }
func (m matchError) Unwrap() error { return m.err }

// asMatchError builds the typed outcome for a --fail-on-match hit.
func asMatchErrorf(format string, args ...any) error {
	return matchError{err: fmt.Errorf(format, args...)}
}

// classifyExitCode maps a command's error to its exit code.
func classifyExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var gate gateError
	if errors.As(err, &gate) {
		return ExitFailOnGate
	}
	var match matchError
	if errors.As(err, &match) {
		return ExitFuzzMatch
	}
	var usage usageError
	if errors.As(err, &usage) {
		return ExitUsageError
	}
	// A refused non-interactive confirmation is a misuse of the command line,
	// not a failure of the work: nothing ran, nothing changed, and the fix is to
	// add --force. Exit 2 puts it in the same bucket as a missing required flag,
	// which is what it is.
	if errors.Is(err, errConfirmationRequired) {
		return ExitUsageError
	}
	return ExitError
}
