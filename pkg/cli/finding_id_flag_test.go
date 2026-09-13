package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestParseFindingIDAcceptsIntegers(t *testing.T) {
	for raw, want := range map[string]int{"": 0, "42": 42, " 42 ": 42, "0": 0} {
		got, err := parseFindingID(raw)
		if err != nil {
			t.Errorf("parseFindingID(%q) errored: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("parseFindingID(%q) = %d, want %d", raw, got, want)
		}
	}
}

// The recorded failure this replaces: a UUID reached pflag and came back naming
// strconv. The caller's next move was to widen the search rather than reach for
// the right flag, so the error has to name that flag.
func TestParseFindingIDExplainsUUIDNamespace(t *testing.T) {
	const u = "3041e25d-2400-4b33-9496-4077d8580f2d"
	_, err := parseFindingID(u)
	if err == nil {
		t.Fatal("a UUID must be rejected, not coerced into a finding ID")
	}
	msg := err.Error()
	for _, want := range []string{
		"traffic --uuid " + u,
		"--agentic-scan " + u,
		"--scan-uuid " + u,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must offer %q, got:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "strconv") {
		t.Errorf("error still names the Go parser rather than the mistake:\n%s", msg)
	}
}

func TestParseFindingIDRejectsJunkWithRecovery(t *testing.T) {
	_, err := parseFindingID("high")
	if err == nil {
		t.Fatal("a non-numeric value must be rejected")
	}
	if !strings.Contains(err.Error(), "vigolium finding -j") {
		t.Errorf("error must show how to list IDs, got:\n%s", err)
	}
}

// Exit code 2 is the contract for "you passed the wrong thing", and a driver
// branches on it; a demotion to 1 makes a fixable mistake look like a failed read.
func TestParseFindingIDErrorsAreUsageErrors(t *testing.T) {
	for _, raw := range []string{"3041e25d-2400-4b33-9496-4077d8580f2d", "high", "-1"} {
		_, err := parseFindingID(raw)
		if err == nil {
			t.Fatalf("parseFindingID(%q) must fail", raw)
		}
		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("parseFindingID(%q) = %T, want a usage error (exit 2)", raw, err)
		}
	}
}
