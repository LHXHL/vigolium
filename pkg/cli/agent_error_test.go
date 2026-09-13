package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

// The point of the code set is that a caller can branch on it. These cases are
// the four source states that used to arrive as one indistinguishable failure,
// each with the message the corresponding read actually produces.
func TestClassifyErrorCodeSeparatesSourceStates(t *testing.T) {
	cases := []struct {
		name string
		err  error
		exit int
		want string
	}{
		{
			name: "missing file",
			err:  fmt.Errorf("failed to open SQLite: database file not readable: %w", fs.ErrNotExist),
			exit: ExitError,
			want: errCodeSourceMissing,
		},
		{
			name: "not a database",
			err:  errors.New("failed to connect to database: failed to open database read-only: file is not a database (26)"),
			exit: ExitError,
			want: errCodeSourceUnreadable,
		},
		{
			name: "valid sqlite, not a vigolium store",
			err:  errors.New("failed to query database: SQL logic error: no such table: http_records (1)"),
			exit: ExitError,
			want: errCodeSourceIncompatible,
		},
		{
			// Matched on the SQLSTATE, so a Postgres server running under a
			// non-English lc_messages still classifies.
			name: "valid postgres db, not a vigolium store",
			err:  errors.New(`ERROR: la relation « http_records » n'existe pas (SQLSTATE=42P01)`),
			exit: ExitError,
			want: errCodeSourceIncompatible,
		},
		{
			name: "genuine query failure",
			err:  errors.New("failed to query database: disk I/O error (10)"),
			exit: ExitError,
			want: errCodeFailed,
		},
		{
			name: "usage error wins over any message match",
			err:  asUsageError(errors.New("unknown --fields name(s): no such table")),
			exit: ExitUsageError,
			want: errCodeUsage,
		},
		{
			name: "gate tripped",
			err:  gateError{err: errors.New("--fail-on high")},
			exit: ExitFailOnGate,
			want: errCodeGateTripped,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyErrorCode(tc.err, tc.exit); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

// The missing-source sentinel has to survive the wrapping it picks up between
// os.Stat and the CLI, or a missing file degrades to the generic code and the
// caller cannot tell "wrong path" from "read broke".
func TestClassifyErrorCodeSeesThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("failed to connect to database: %w",
		fmt.Errorf("failed to open SQLite: %w", fs.ErrNotExist))
	if got := classifyErrorCode(wrapped, ExitError); got != errCodeSourceMissing {
		t.Errorf("wrapped missing source: code = %q, want %q", got, errCodeSourceMissing)
	}
}
