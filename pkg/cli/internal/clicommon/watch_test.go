package clicommon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The validation ran AFTER the first fn() call, so `--watch nonsense` executed
// the query, printed a result, and only then reported that the interval was
// unparseable. A check that fires after the side effect is not a check.
func TestInvalidIntervalRejectedBeforeTheFirstRun(t *testing.T) {
	cases := []string{"nonsense", "5x", "-3", "1zz"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			ran := 0
			err := RunWithWatchOptions(WatchOptions{Raw: raw}, func() error {
				ran++
				return nil
			})
			if err == nil {
				t.Fatalf("--watch %q must be rejected", raw)
			}
			if ran != 0 {
				t.Errorf("fn ran %d time(s) before the interval was validated", ran)
			}
			if !strings.Contains(err.Error(), "--watch") {
				t.Errorf("the rejection must name the flag, got: %v", err)
			}
		})
	}
}

func TestZeroIntervalRunsExactlyOnce(t *testing.T) {
	ran := 0
	if err := RunWithWatchOptions(WatchOptions{Raw: ""}, func() error {
		ran++
		return nil
	}); err != nil {
		t.Fatalf("no watch requested: %v", err)
	}
	if ran != 1 {
		t.Errorf("fn ran %d times, want exactly 1 when watch is off", ran)
	}
}

// Repeating a WRITE on a timer is never what --watch means. Obeying it there
// would re-run a delete every N seconds.
func TestWatchRejectedForAMutatingOperation(t *testing.T) {
	ran := 0
	err := RunWithWatchOptions(WatchOptions{Raw: "1s", Mutates: true}, func() error {
		ran++
		return nil
	})
	if err == nil {
		t.Fatal("--watch on a mutating command must be rejected")
	}
	if !errors.Is(err, ErrWatchNotSupported) {
		t.Errorf("error = %v, want one wrapping ErrWatchNotSupported", err)
	}
	if ran != 0 {
		t.Errorf("the write ran %d time(s) despite the rejection", ran)
	}
}

func TestErrorFromTheFirstRunPropagates(t *testing.T) {
	want := errors.New("query failed")
	err := RunWithWatchOptions(WatchOptions{Raw: "1s"}, func() error { return want })
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}

func TestParseWatchInterval(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"5", 5 * time.Second, false},  // bare integers are seconds
		{"5s", 5 * time.Second, false}, // and duration syntax still works
		{"2m", 2 * time.Minute, false},
		{"nope", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseWatchInterval(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseWatchInterval(%q) error = %v, wantErr %v", tc.raw, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseWatchInterval(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
