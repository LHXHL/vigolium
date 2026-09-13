package cli

import (
	"errors"
	"testing"
)

func resetPresentationFlags(t *testing.T) {
	t.Helper()
	globalJSON, globalSilent, globalSoftFail, globalCIOutput = false, false, false, false
	t.Cleanup(func() {
		globalJSON, globalSilent, globalSoftFail, globalCIOutput = false, false, false, false
	})
}

// Flag ORDER used to decide whether a failed command answered in JSON at all:
// cobra binds globalJSON during parsing, so when parsing is what failed the
// flag was never bound and the error path emitted nothing.
//
//	vigolium traffic --json --definitely-invalid  -> one JSON usage_error
//	vigolium traffic --definitely-invalid --json  -> empty stdout
func TestPresentationModeRecoveredFromArgvAfterAParseFailure(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"json after the bad flag", []string{"traffic", "--definitely-invalid", "--json"}, true},
		{"json before the bad flag", []string{"traffic", "--json", "--definitely-invalid"}, true},
		{"long assignment form", []string{"traffic", "--definitely-invalid", "--json=true"}, true},
		{"shorthand", []string{"traffic", "--definitely-invalid", "-j"}, true},
		{"global before the command", []string{"--json", "traffic", "--definitely-invalid"}, true},
		{"alias", []string{"tf", "--definitely-invalid", "--json"}, true},
		{"not requested", []string{"traffic", "--definitely-invalid"}, false},
		// An explicit false must stay false; the old argv scan compared whole
		// arguments and would have missed this either way.
		{"explicit false", []string{"traffic", "--definitely-invalid", "--json=false"}, false},
		// After the terminator the token is a positional argument, not a flag.
		{"after the -- terminator", []string{"traffic", "--", "--json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPresentationFlags(t)
			resolvePresentationMode(tc.args)
			if globalJSON != tc.want {
				t.Errorf("globalJSON = %v, want %v for %v", globalJSON, tc.want, tc.args)
			}
		})
	}
}

func TestPresentationModeRecoversSoftFailAndSilent(t *testing.T) {
	resetPresentationFlags(t)
	resolvePresentationMode([]string{"traffic", "--definitely-invalid", "--soft-fail", "--silent"})

	if !globalSoftFail {
		t.Error("--soft-fail must be recovered; otherwise a parse failure exits non-zero for a caller that opted out")
	}
	if !globalSilent {
		t.Error("--silent must be recovered")
	}
}

func TestPresentationModeDoesNotUnsetAnAlreadyResolvedMode(t *testing.T) {
	resetPresentationFlags(t)
	globalJSON = true
	// A successful parse already resolved the mode; the recovery must not
	// second-guess it from argv.
	resolvePresentationMode([]string{"traffic"})
	if !globalJSON {
		t.Error("an already-resolved presentation mode must be left alone")
	}
}

// The three utilities that report a match used to call os.Exit(ExitFuzzMatch)
// straight from their handler, skipping every deferred close and jumping over
// Execute — so --soft-fail, documented as forcing a successful exit everywhere,
// silently did not apply to the exit code most likely to be gated in CI.
func TestMatchOutcomeIsATypedErrorNotADirectExit(t *testing.T) {
	err := asMatchErrorf("--fail-on-match: %d secret(s) matched", 2)

	if got := classifyExitCode(err); got != ExitFuzzMatch {
		t.Errorf("exit code = %d, want %d", got, ExitFuzzMatch)
	}
	var match matchError
	if !errors.As(err, &match) {
		t.Error("a match outcome must be recognizable by type, not by message text")
	}
	// A match is a completed result, so it must not be confused with the
	// severity gate or with an execution failure.
	if classifyExitCode(err) == ExitFailOnGate || classifyExitCode(err) == ExitError {
		t.Error("a match is neither a gate trip nor a failure")
	}
}

func TestGateAndMatchRemainDistinct(t *testing.T) {
	gate := gateError{err: errors.New("high severity finding")}
	match := asMatchErrorf("matched")

	if classifyExitCode(gate) == classifyExitCode(match) {
		t.Error("a severity gate (4) and a fuzz match (3) are different outcomes and must not collapse")
	}
}
