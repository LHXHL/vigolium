package config

import (
	"slices"
	"testing"
	"time"
)

func TestResolvePhase_ConcurrencyFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		Discovery: PhasePace{
			ConcurrencyFactor: 0.5,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	if resolved.Concurrency != 25 {
		t.Errorf("expected concurrency 25, got %d", resolved.Concurrency)
	}
	if resolved.ConcurrencyFactor != 0.5 {
		t.Errorf("expected ConcurrencyFactor 0.5, got %f", resolved.ConcurrencyFactor)
	}
}

func TestResolvePhase_ConcurrencyFactor_Rounding(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 33,
		Spidering: PhasePace{
			ConcurrencyFactor: 0.5,
		},
	}
	resolved := cfg.ResolvePhase("spidering")
	// 33 * 0.5 = 16.5 → rounds to 17
	if resolved.Concurrency != 17 {
		t.Errorf("expected concurrency 17 (rounded), got %d", resolved.Concurrency)
	}
}

func TestResolvePhase_DurationFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			DurationFactor: 3.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	expected := 90 * time.Minute
	if resolved.MaxDuration != expected {
		t.Errorf("expected max_duration %v, got %v", expected, resolved.MaxDuration)
	}
	if resolved.DurationFactor != 3.0 {
		t.Errorf("expected DurationFactor 3.0, got %f", resolved.DurationFactor)
	}
}

func TestResolvePhase_DurationFactor_Fractional(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "30m",
		ExternalHarvester: PhasePace{
			DurationFactor: 0.2,
		},
	}
	resolved := cfg.ResolvePhase("external_harvester")
	expected := 6 * time.Minute
	if resolved.MaxDuration != expected {
		t.Errorf("expected max_duration %v, got %v", expected, resolved.MaxDuration)
	}
}

func TestResolvePhase_ExplicitOverridesFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		DynamicAssessment: PhasePace{
			Concurrency:       30,
			ConcurrencyFactor: 0.8, // ignored because concurrency is set
			MaxDuration:       "1h",
			DurationFactor:    2.0, // ignored because max_duration is set
		},
	}
	resolved := cfg.ResolvePhase("dynamic-assessment")
	if resolved.Concurrency != 30 {
		t.Errorf("expected concurrency 30 (explicit), got %d", resolved.Concurrency)
	}
	if resolved.ConcurrencyFactor != 0 {
		t.Errorf("expected ConcurrencyFactor 0 (not applied), got %f", resolved.ConcurrencyFactor)
	}
	if resolved.MaxDuration != time.Hour {
		t.Errorf("expected max_duration 1h (explicit), got %v", resolved.MaxDuration)
	}
	if resolved.DurationFactor != 0 {
		t.Errorf("expected DurationFactor 0 (not applied), got %f", resolved.DurationFactor)
	}
}

func TestResolvePhase_FactorZero_FallsThrough(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			ConcurrencyFactor: 0, // zero = not set, use common
			DurationFactor:    0, // zero = not set, use common
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	if resolved.Concurrency != 50 {
		t.Errorf("expected concurrency 50 (common fallback), got %d", resolved.Concurrency)
	}
	if resolved.MaxDuration != 30*time.Minute {
		t.Errorf("expected max_duration 30m (common fallback), got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_CommonMaxDuration(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "15m",
	}
	resolved := cfg.ResolvePhase("spidering")
	if resolved.MaxDuration != 15*time.Minute {
		t.Errorf("expected max_duration 15m from common, got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_NoCommonMaxDuration_FactorIgnored(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Discovery: PhasePace{
			DurationFactor: 2.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	// No common max_duration, so factor has nothing to scale
	if resolved.MaxDuration != 0 {
		t.Errorf("expected max_duration 0 (no common to scale), got %v", resolved.MaxDuration)
	}
}

func TestResolvePhase_ConcurrencyFactor_ZeroCommon(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 0,
		Discovery: PhasePace{
			ConcurrencyFactor: 2.0,
		},
	}
	resolved := cfg.ResolvePhase("discovery")
	// Common concurrency is 0, factor has nothing to scale
	if resolved.Concurrency != 0 {
		t.Errorf("expected concurrency 0, got %d", resolved.Concurrency)
	}
}

func TestValidate_NegativeConcurrencyFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Discovery: PhasePace{
			ConcurrencyFactor: -1.0,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative concurrency_factor")
	}
}

func TestValidate_NegativeDurationFactor(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Spidering: PhasePace{
			DurationFactor: -0.5,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative duration_factor")
	}
}

func TestValidate_InvalidCommonMaxDuration(t *testing.T) {
	cfg := &ScanningPaceConfig{
		MaxDuration: "not-a-duration",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid common max_duration")
	}
}

func TestDefaultScanningPaceConfig(t *testing.T) {
	cfg := DefaultScanningPaceConfig()

	if cfg.MaxDuration != "45m" {
		t.Errorf("expected default max_duration '45m', got %q", cfg.MaxDuration)
	}

	// Verify per-phase duration factors are set
	tests := []struct {
		phase  string
		factor float64
	}{
		{"discovery", 0.5},
		{"known-issue-scan", 0.5},
		{"spidering", 0.1},
		{"external_harvester", 0.1},
		{"dynamic-assessment", 1.0},
	}
	for _, tt := range tests {
		resolved := cfg.ResolvePhase(tt.phase)
		if resolved.DurationFactor != tt.factor {
			t.Errorf("phase %s: expected duration_factor %v, got %v", tt.phase, tt.factor, resolved.DurationFactor)
		}
		if resolved.MaxDuration == 0 {
			t.Errorf("phase %s: expected non-zero resolved max_duration", tt.phase)
		}
	}
}

// TestDefaultPace_EveryPhaseHasFiniteBudget pins the resolved max_duration each
// phase gets from the shipped default config (45m base). Every scan/network
// phase must resolve a non-zero, finite budget — a zero here means an unbounded
// phase, the class of bug that let known-issue-scan overrun its limit. Update the
// expected values deliberately if the default factors change.
func TestDefaultPace_EveryPhaseHasFiniteBudget(t *testing.T) {
	cfg := DefaultScanningPaceConfig()

	want := map[string]time.Duration{
		"discovery":          22*time.Minute + 30*time.Second, // 45m * 0.5
		"spidering":          4*time.Minute + 30*time.Second,  // 45m * 0.1
		"known-issue-scan":   22*time.Minute + 30*time.Second, // 45m * 0.5
		"external_harvester": 4*time.Minute + 30*time.Second,  // 45m * 0.1
		"dynamic-assessment": 45 * time.Minute,                // 45m * 1.0
	}

	for phase, expected := range want {
		resolved := cfg.ResolvePhase(phase)
		if resolved.MaxDuration <= 0 {
			t.Errorf("phase %q resolved to an unbounded max_duration (%v)", phase, resolved.MaxDuration)
			continue
		}
		if resolved.MaxDuration != expected {
			t.Errorf("phase %q: resolved max_duration = %v, want %v", phase, resolved.MaxDuration, expected)
		}
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &ScanningPaceConfig{
		Concurrency: 50,
		MaxDuration: "30m",
		Discovery: PhasePace{
			ConcurrencyFactor: 0.5,
			DurationFactor:    2.0,
		},
		Spidering: PhasePace{
			DurationFactor: 1.0,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

// TestPhaseSectionNamesMatchSection holds paceSectionNames and Section's switch
// together. They are two hand-maintained lists of the same vocabulary, and the
// failure mode when they drift is silent: a phase missing from the names list
// is never validated and never reachable via a --rate-limit qualifier, while a
// name with no section makes Validate dereference a nil *PhasePace and panic.
func TestPhaseSectionNamesMatchSection(t *testing.T) {
	cfg := &ScanningPaceConfig{}

	// Every advertised name must resolve to a distinct section.
	seen := map[*PhasePace]string{}
	for _, name := range PhaseSectionNames() {
		section := cfg.Section(name)
		if section == nil {
			t.Errorf("PhaseSectionNames advertises %q but Section returns nil for it", name)
			continue
		}
		if other, dup := seen[section]; dup {
			t.Errorf("phases %q and %q resolve to the same section", other, name)
		}
		seen[section] = name
	}

	// Every phase the native scan can run and that is paceable must be
	// advertised. This is the direction that actually bit: a phase added to the
	// struct and the switch, but not to the names list, is silently unpaced.
	for _, name := range []string{
		"discovery", "probe", "spidering",
		"known-issue-scan", "external-harvest", "dynamic-assessment",
	} {
		if cfg.Section(name) == nil {
			t.Errorf("Section(%q) returned nil; every paceable phase needs a section", name)
		}
		if !slices.Contains(PhaseSectionNames(), name) {
			t.Errorf("PhaseSectionNames omits %q", name)
		}
	}
}
