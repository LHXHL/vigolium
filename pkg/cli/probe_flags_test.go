package cli

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// withExportScopeReset restores the scan path's export state between tests.
func withExportScopeReset(t *testing.T) {
	t.Helper()
	savedScope, savedFlag := scanExportScope, scanExportOnly
	t.Cleanup(func() {
		scanExportScope, scanExportOnly = savedScope, savedFlag
	})
	scanExportScope, scanExportOnly = fullExportScope, nil
}

func TestApplyExportScopeProbeOnly(t *testing.T) {
	withExportScopeReset(t)

	opts := &types.Options{ProbeEnabled: true, OnlyPhase: "probe"}
	if err := applyExportScope(opts); err != nil {
		t.Fatalf("applyExportScope: %v", err)
	}

	// On a sweep the findings are all "Technology Detected: X" and that verdict
	// now rides on the record's own technology field, so emitting both states the
	// same thing twice.
	if !scanExportScope.includes("http") || scanExportScope.includes("findings") {
		t.Errorf("scope = %v, want http only", scanExportScope.only)
	}
	// The narrowing must NOT reach the `export` command's global, which gates
	// every other format through the same streamExportData: writing it there made
	// `run probe -o r.html --format html` render a findings-free report.
	if topExportOnly != nil {
		t.Errorf("topExportOnly = %v, want nil - the scan must not narrow the export command's scope", topExportOnly)
	}
}

// TestApplyExportScopeFullScanKeepsEverything is the guard that matters: a real
// scan's findings are not derivable from its records, so narrowing the envelope
// there would silently drop results.
func TestApplyExportScopeFullScanKeepsEverything(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts *types.Options
	}{
		{"full scan", &types.Options{}},
		{"probe alongside other phases", &types.Options{ProbeEnabled: true}},
		{"a different single phase", &types.Options{OnlyPhase: "scanning"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withExportScopeReset(t)
			if err := applyExportScope(tc.opts); err != nil {
				t.Fatalf("applyExportScope: %v", err)
			}
			if !scanExportScope.includes("findings") || !scanExportScope.includes("http") {
				t.Errorf("scope = %v, want the whole envelope", scanExportScope.only)
			}
		})
	}
}

func TestApplyExportScopeExplicitFlagWins(t *testing.T) {
	withExportScopeReset(t)
	scanExportOnly = []string{"http", "findings"}

	opts := &types.Options{ProbeEnabled: true, OnlyPhase: "probe"}
	if err := applyExportScope(opts); err != nil {
		t.Fatalf("applyExportScope: %v", err)
	}
	if !scanExportScope.includes("http") || !scanExportScope.includes("findings") {
		t.Errorf("scope = %v, want [http findings] - an explicit --export-only must beat the probe default",
			scanExportScope.only)
	}
	if scanExportScope.includes("scans") {
		t.Errorf("scope = %v, want scans excluded", scanExportScope.only)
	}
}

// TestApplyExportScopeTrimsValues guards the normalization. pflag's CSV parser
// keeps the space in `--export-only "http, findings"`, and comparing the raw
// value validated fine but then matched no type at all.
func TestApplyExportScopeTrimsValues(t *testing.T) {
	withExportScopeReset(t)
	scanExportOnly = []string{"http", " findings"}

	if err := applyExportScope(&types.Options{}); err != nil {
		t.Fatalf("applyExportScope: %v", err)
	}
	if !scanExportScope.includes("findings") {
		t.Errorf("scope = %v, want a space-padded value to still match", scanExportScope.only)
	}
}

func TestApplyExportScopeRejectsUnknownType(t *testing.T) {
	withExportScopeReset(t)
	scanExportOnly = []string{"http", "nonsense"}

	if err := applyExportScope(&types.Options{}); err == nil {
		t.Fatal("applyExportScope accepted an unknown --export-only value")
	}
}
