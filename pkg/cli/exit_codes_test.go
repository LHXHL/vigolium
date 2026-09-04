package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyExitCodeSeparatesGateFromError(t *testing.T) {
	// The change this table exists for: a scan that ran cleanly and found a
	// high-severity finding is the OPPOSITE outcome from one that failed to
	// start, and both used to exit 1.
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitSuccess},
		{"plain error", errors.New("boom"), ExitError},
		{"usage error", asUsageError(errors.New("bad combo")), ExitUsageError},
		{"fail-on gate", gateError{err: errors.New("--fail-on high")}, ExitFailOnGate},
	}
	for _, tc := range cases {
		if got := classifyExitCode(tc.err); got != tc.want {
			t.Errorf("%s: exit = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestClassifyExitCodeSeesThroughWrapping(t *testing.T) {
	// Errors are wrapped on their way up through the run path; a gate that stops
	// being recognised after one %w is a gate that silently exits 1.
	wrapped := fmt.Errorf("scan failed: %w", gateError{err: errors.New("gate")})
	if got := classifyExitCode(wrapped); got != ExitFailOnGate {
		t.Errorf("wrapped gate: exit = %d, want %d", got, ExitFailOnGate)
	}
	wrappedUsage := fmt.Errorf("context: %w", asUsageError(errors.New("bad flag")))
	if got := classifyExitCode(wrappedUsage); got != ExitUsageError {
		t.Errorf("wrapped usage: exit = %d, want %d", got, ExitUsageError)
	}
}

func TestAsUsageErrorPassesNilThrough(t *testing.T) {
	// So a call site can wrap its return value directly.
	if err := asUsageError(nil); err != nil {
		t.Errorf("asUsageError(nil) = %v, want nil", err)
	}
}

func TestUsageErrorPreservesMessage(t *testing.T) {
	err := asUsageError(errors.New("--all-hosts is required"))
	if err.Error() != "--all-hosts is required" {
		t.Errorf("message rewritten: %q", err.Error())
	}
}

func TestIsFlagParseError(t *testing.T) {
	// A flag-parse failure never reaches a RunE, so it cannot be wrapped at its
	// source; recognising it here is what keeps "unknown flag" at 2.
	for msg, want := range map[string]bool{
		"unknown flag: --bogus":             true,
		"unknown shorthand flag: 'S' in -S": true,
		"flag needs an argument: --db":      true,
		"accepts 1 arg(s), received 2":      true,
		"connection refused":                false,
		"failed to open database":           false,
	} {
		if got := isFlagParseError(errors.New(msg)); got != want {
			t.Errorf("isFlagParseError(%q) = %v, want %v", msg, got, want)
		}
	}
}
