package cli

import (
	"testing"
)

// withDBIsolateGlobals pins the two package vars dbIsolateYieldsToStateless
// touches and restores them afterwards. Narrower than withGlobals (which owns
// --format/--db too) because this helper also has to pin globalSilent, to keep
// the warning off the test log.
func withDBIsolateGlobals(t *testing.T, isolate bool) {
	t.Helper()
	prevIsolate, prevSilent := globalDBIsolate, globalSilent
	globalDBIsolate, globalSilent = isolate, true
	t.Cleanup(func() { globalDBIsolate, globalSilent = prevIsolate, prevSilent })
}

// TestDBIsolateYieldsToStateless pins the precedence rule. The assertion is on
// globalDBIsolate rather than a return value because clearing that var IS the
// mechanism: dbIsolateBegin reads it directly, so a rule that only reported the
// conflict would still let a scratch database be merged into the throwaway
// stateless one moments before it is deleted.
func TestDBIsolateYieldsToStateless(t *testing.T) {
	tests := []struct {
		name        string
		stateless   bool
		isolate     bool
		wantIsolate bool
	}{
		{
			name:        "stateless clears db-isolate",
			stateless:   true,
			isolate:     true,
			wantIsolate: false,
		},
		{
			name:        "db-isolate alone is untouched",
			stateless:   false,
			isolate:     true,
			wantIsolate: true,
		},
		{
			name:      "stateless alone has nothing to clear",
			stateless: true,
			isolate:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withDBIsolateGlobals(t, tt.isolate)

			dbIsolateYieldsToStateless(tt.stateless)

			if globalDBIsolate != tt.wantIsolate {
				t.Errorf("globalDBIsolate = %v, want %v", globalDBIsolate, tt.wantIsolate)
			}
		})
	}
}
