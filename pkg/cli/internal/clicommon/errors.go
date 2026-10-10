package clicommon

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// The error types the CLI's exit-code classifier recognises. They live here,
// not in pkg/cli, so every command package (configcmd and any future split-out
// group) can return a usage error or a coded error without importing pkg/cli,
// which would be a cycle. pkg/cli keeps short unexported aliases so its own call
// sites read the same as before.

// UsageError marks an error as a misuse of the command line (an unknown flag
// value, a rejected combination, a missing required flag) rather than a failure
// of the work. It exits 2 with error.code "usage_error". Cobra's own flag-parse
// errors are classified separately, because they never pass through here.
type UsageError struct{ Err error }

func (u UsageError) Error() string { return u.Err.Error() }
func (u UsageError) Unwrap() error { return u.Err }

// AsUsageError wraps err so the command exits 2. It returns nil for a nil
// error, so a call site can wrap its return value directly.
func AsUsageError(err error) error {
	if err == nil {
		return nil
	}
	return UsageError{Err: err}
}

// UsageErrorf builds a usage error (exit 2) from a format string, for the
// common case of rejecting a bad flag value at its own call site.
func UsageErrorf(format string, args ...any) error {
	return UsageError{Err: fmt.Errorf(format, args...)}
}

// CodedError carries a stable error code alongside its message, for conditions
// the classifier cannot infer from an exit code or a wrapped sentinel. It exits
// 1 unless the code is one of the incomplete codes (see IncompleteError).
//
// The alternative was matching on message text: a code a consumer branches on
// must not depend on how the sentence around it is worded.
type CodedError struct {
	code apicontract.ErrorCode
	err  error
}

func (c CodedError) Error() string               { return c.err.Error() }
func (c CodedError) Unwrap() error               { return c.err }
func (c CodedError) Code() apicontract.ErrorCode { return c.code }

// NewCodedError wraps err with the given stable code.
func NewCodedError(code apicontract.ErrorCode, err error) error {
	return CodedError{code: code, err: err}
}

// CodedErrorf builds an error that reports the given stable code.
func CodedErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	return CodedError{code: code, err: fmt.Errorf(format, args...)}
}

// IncompleteError marks work that ran but did not finish: a time budget fired
// (timed_out), a request or token budget ran out (budget_exhausted), or some of
// the work failed while the rest completed (partial). It exits 5.
//
// Like the --fail-on gate it is a completed result, not a failure: the caller
// writes its output first and returns this afterwards, so the result document
// is already on stdout and no error document is appended. --soft-fail forces 0.
type IncompleteError struct {
	code apicontract.ErrorCode
	err  error
}

func (i IncompleteError) Error() string               { return i.err.Error() }
func (i IncompleteError) Unwrap() error               { return i.err }
func (i IncompleteError) Code() apicontract.ErrorCode { return i.code }

// IncompleteErrorf builds an incomplete-result error. code should satisfy
// code.IsIncomplete(); any other code falls back to "partial" so the exit
// status and the reported code cannot disagree.
func IncompleteErrorf(code apicontract.ErrorCode, format string, args ...any) error {
	if !code.IsIncomplete() {
		code = apicontract.CodePartial
	}
	return IncompleteError{code: code, err: fmt.Errorf(format, args...)}
}
