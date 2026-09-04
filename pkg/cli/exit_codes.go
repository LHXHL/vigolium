package cli

import "errors"

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

// gateError marks the --fail-on severity gate. It is not a failure: the scan ran
// to completion and its output was written before this is returned. A consumer
// distinguishing "found something" from "broke" reads exit 4 vs exit 1.
type gateError struct{ err error }

func (g gateError) Error() string { return g.err.Error() }
func (g gateError) Unwrap() error { return g.err }

// classifyExitCode maps a command's error to its exit code.
func classifyExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var gate gateError
	if errors.As(err, &gate) {
		return ExitFailOnGate
	}
	var usage usageError
	if errors.As(err, &usage) {
		return ExitUsageError
	}
	return ExitError
}
