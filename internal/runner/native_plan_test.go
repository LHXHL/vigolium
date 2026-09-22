package runner

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestNormalizeNativePhase_Aliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"deparos", "discovery"},
		{"discover", "discovery"},
		{"spitolas", "spidering"},
		{"ext", "extension"},
		{"audit", "dynamic-assessment"},
		{"dast", "dynamic-assessment"},
		{"assessment", "dynamic-assessment"},
		{"dynamic-assessment", "dynamic-assessment"},
		{"discovery", "discovery"},
		{"cve", "known-issue-scan"},
		{"kis", "known-issue-scan"},
		{"known-issues", "known-issue-scan"},
		{"known-issue-scan", "known-issue-scan"},
		// Symmetry with "discover": the spidering phase used to have no short
		// spelling, so `run discover` worked and `run spider` was an error.
		{"spider", "spidering"},
		{"spidering", "spidering"},
		{"crawl", "spidering"},
		{"crawling", "spidering"},
		{"discovering", "discovery"},
		{"harvest", "external-harvest"},
		{"harvesting", "external-harvest"},
		{"external_harvester", "external-harvest"},
		{"ingest", "ingestion"},
		{"assess", "dynamic-assessment"},
		{"extensions", "extension"},
		// Case and surrounding whitespace are normalized away.
		{"  Spider ", "spidering"},
		{"DISCOVER", "discovery"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		if got := NormalizeNativePhase(tt.input); got != tt.want {
			t.Errorf("NormalizeNativePhase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestPhaseVocabularyIsSelfConsistent locks the property the single table
// exists for: every spelling the vocabulary advertises resolves, and everything
// that resolves is advertised. A hand-maintained valid-list is exactly what
// drifted before — `spider` normalized nowhere while the help text implied a
// full set of aliases.
func TestPhaseVocabularyIsSelfConsistent(t *testing.T) {
	for _, p := range nativePhaseVocabulary {
		if got := NormalizeNativePhase(p.Canonical); got != p.Canonical {
			t.Errorf("canonical %q normalized to %q", p.Canonical, got)
		}
		if !IsNativePhaseSpelling(p.Canonical) {
			t.Errorf("canonical %q not recognized as a phase spelling", p.Canonical)
		}
		for _, a := range p.Aliases {
			if got := NormalizeNativePhase(a); got != p.Canonical {
				t.Errorf("alias %q normalized to %q, want %q", a, got, p.Canonical)
			}
			// An alias must be accepted wherever its canonical is, so --only
			// never rejects a spelling the help text lists.
			if _, _, err := parseOnlyPhases(a); err != nil {
				t.Errorf("parseOnlyPhases(%q) rejected an advertised alias: %v", a, err)
			}
		}
	}

	// No spelling may be claimed by two phases: the index would silently keep
	// whichever entry was built last.
	seen := make(map[string]string)
	for _, p := range nativePhaseVocabulary {
		for _, s := range append([]string{p.Canonical}, p.Aliases...) {
			if owner, dup := seen[s]; dup {
				t.Errorf("spelling %q claimed by both %q and %q", s, owner, p.Canonical)
			}
			seen[s] = p.Canonical
		}
	}
}

// TestSkippableVocabularyMatchesSkipDispatch keeps the Skippable column honest:
// it drives the --skip help text and error message, while the actual behaviour
// lives in ApplyNativePhaseSelection's switch. A phase listed as skippable that
// the switch rejects would advertise a flag value that always errors.
func TestSkippableVocabularyMatchesSkipDispatch(t *testing.T) {
	for _, p := range nativePhaseVocabulary {
		opts := &types.Options{SkipPhases: []string{p.Canonical}}
		err := ApplyNativePhaseSelection(opts, nil)
		if p.Skippable && err != nil {
			t.Errorf("--skip %s is advertised as skippable but was rejected: %v", p.Canonical, err)
		}
		if !p.Skippable && err == nil {
			t.Errorf("--skip %s is not advertised as skippable but was accepted", p.Canonical)
		}
	}
}

func TestApplyNativePhaseSelection_OnlyPhase(t *testing.T) {
	type want struct {
		onlyPhase             string
		discoverEnabled       bool
		spideringEnabled      bool
		externalHarvest       bool
		knownIssue            bool
		skipIngestion         bool
		skipDynamicAssessment bool
		extensionsOnly        bool
	}
	tests := []struct {
		name  string
		input string
		want  want
	}{
		{
			name:  "single spidering",
			input: "spidering",
			want: want{
				onlyPhase:             "spidering",
				spideringEnabled:      true,
				skipIngestion:         true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "single discovery keeps ingestion",
			input: "discovery",
			want: want{
				onlyPhase:             "discovery",
				discoverEnabled:       true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "comma-separated spidering and discovery",
			input: "spidering,discovery",
			want: want{
				onlyPhase:             "spidering,discovery",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "alias normalization with whitespace",
			input: "spitolas, deparos",
			want: want{
				onlyPhase:             "spidering,discovery",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "spidering plus dynamic-assessment runs both",
			input: "spidering,dynamic-assessment",
			want: want{
				onlyPhase:        "spidering,dynamic-assessment",
				spideringEnabled: true,
				skipIngestion:    true,
			},
		},
		{
			name:  "extension flips ExtensionsOnly",
			input: "extension",
			want: want{
				onlyPhase:      "extension",
				skipIngestion:  true,
				extensionsOnly: true,
			},
		},
		{
			name:  "duplicates collapse",
			input: "discovery,discovery,spidering",
			want: want{
				onlyPhase:             "discovery,spidering",
				discoverEnabled:       true,
				spideringEnabled:      true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "cve alias resolves to known-issue-scan",
			input: "cve",
			want: want{
				onlyPhase:             "known-issue-scan",
				knownIssue:            true,
				skipIngestion:         true,
				skipDynamicAssessment: true,
			},
		},
		{
			name:  "kis alias resolves to known-issue-scan",
			input: "kis",
			want: want{
				onlyPhase:             "known-issue-scan",
				knownIssue:            true,
				skipIngestion:         true,
				skipDynamicAssessment: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &types.Options{OnlyPhase: tt.input}
			if err := ApplyNativePhaseSelection(opts, nil); err != nil {
				t.Fatalf("ApplyNativePhaseSelection: %v", err)
			}
			if opts.OnlyPhase != tt.want.onlyPhase {
				t.Errorf("OnlyPhase = %q, want %q", opts.OnlyPhase, tt.want.onlyPhase)
			}
			if opts.DiscoverEnabled != tt.want.discoverEnabled {
				t.Errorf("DiscoverEnabled = %v, want %v", opts.DiscoverEnabled, tt.want.discoverEnabled)
			}
			if opts.SpideringEnabled != tt.want.spideringEnabled {
				t.Errorf("SpideringEnabled = %v, want %v", opts.SpideringEnabled, tt.want.spideringEnabled)
			}
			if opts.ExternalHarvestEnabled != tt.want.externalHarvest {
				t.Errorf("ExternalHarvestEnabled = %v, want %v", opts.ExternalHarvestEnabled, tt.want.externalHarvest)
			}
			if opts.KnownIssueScanEnabled != tt.want.knownIssue {
				t.Errorf("KnownIssueScanEnabled = %v, want %v", opts.KnownIssueScanEnabled, tt.want.knownIssue)
			}
			if opts.SkipIngestion != tt.want.skipIngestion {
				t.Errorf("SkipIngestion = %v, want %v", opts.SkipIngestion, tt.want.skipIngestion)
			}
			if opts.SkipDynamicAssessment != tt.want.skipDynamicAssessment {
				t.Errorf("SkipDynamicAssessment = %v, want %v", opts.SkipDynamicAssessment, tt.want.skipDynamicAssessment)
			}
			if opts.ExtensionsOnly != tt.want.extensionsOnly {
				t.Errorf("ExtensionsOnly = %v, want %v", opts.ExtensionsOnly, tt.want.extensionsOnly)
			}
		})
	}
}

func TestApplyNativePhaseSelection_SkipDiscoveryClearsDiscoverEnabled(t *testing.T) {
	// A strategy (e.g. balanced) may have enabled DiscoverEnabled before phase
	// selection runs. --skip discovery must both skip ingestion AND clear
	// DiscoverEnabled so the config panel reports the phase as off and no
	// downstream gate still sees discovery as active.
	opts := &types.Options{
		DiscoverEnabled: true,
		SkipPhases:      []string{"discovery"},
	}
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatalf("ApplyNativePhaseSelection: %v", err)
	}
	if !opts.SkipIngestion {
		t.Errorf("SkipIngestion = false, want true")
	}
	if opts.DiscoverEnabled {
		t.Errorf("DiscoverEnabled = true, want false after --skip discovery")
	}

	// The native plan derived from these opts must not include PhaseDiscovery.
	plan := BuildNativeScanPlan(opts)
	for _, step := range plan.Steps {
		if step.Phase == PhaseDiscovery && step.Enabled {
			t.Errorf("PhaseDiscovery still enabled in plan after --skip discovery")
		}
	}
}

func TestApplyNativePhaseSelection_OnlyPhaseErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"unknown phase", "bogus"},
		{"mixed valid + invalid", "discovery,bogus"},
		{"only commas", ",,,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &types.Options{OnlyPhase: tt.input}
			if err := ApplyNativePhaseSelection(opts, nil); err == nil {
				t.Errorf("expected error for input %q", tt.input)
			}
		})
	}
}

// TestProbeOnlyDefaults pins the defaults a standalone host sweep gives itself,
// and that each one yields to an operator who asked for something else. They
// live in ApplyNativePhaseSelection rather than the CLI so that the REST API and
// the programmatic launcher — which call the same function — run the probe phase
// identically; a regression here is a phase that behaves differently depending
// on how it was started.
func TestProbeOnlyDefaults(t *testing.T) {
	probeOnly := func() *types.Options {
		return &types.Options{OnlyPhase: "probe"}
	}

	t.Run("applied for a probe-only run", func(t *testing.T) {
		opts := probeOnly()
		if err := ApplyNativePhaseSelection(opts, nil); err != nil {
			t.Fatalf("ApplyNativePhaseSelection: %v", err)
		}
		if !opts.ProbeEnabled {
			t.Fatal("ProbeEnabled = false")
		}
		if !opts.RecordRedirectChain {
			t.Error("RecordRedirectChain = false; a sweep is mostly redirects and must record the hops")
		}
		if opts.RedirectMode != http.RedirectModeSameApex {
			t.Errorf("RedirectMode = %q, want same-apex", opts.RedirectMode)
		}
		if opts.TransportProfile != http.TransportProfileSweep {
			t.Errorf("TransportProfile = %q, want sweep", opts.TransportProfile)
		}
		if !opts.NoWafPacing {
			t.Error("NoWafPacing = false; one request per host has no burst for the pre-arm to pre-empt")
		}
	})

	t.Run("an explicit choice always wins", func(t *testing.T) {
		opts := probeOnly()
		opts.RedirectMode = http.RedirectModeOff
		opts.TransportProfile = "custom"
		opts.RecordRedirectChainSet = true // operator typed --record-redirect-chain=false
		opts.NoWafPacingSet = true         // operator typed --no-waf-pacing=false
		if err := ApplyNativePhaseSelection(opts, nil); err != nil {
			t.Fatalf("ApplyNativePhaseSelection: %v", err)
		}
		if opts.RedirectMode != http.RedirectModeOff {
			t.Errorf("RedirectMode = %q, want the operator's off", opts.RedirectMode)
		}
		if opts.TransportProfile != "custom" {
			t.Errorf("TransportProfile = %q, want the operator's custom", opts.TransportProfile)
		}
		if opts.RecordRedirectChain {
			t.Error("RecordRedirectChain was defaulted on over an explicit false")
		}
		if opts.NoWafPacing {
			t.Error("NoWafPacing was defaulted on over an explicit false")
		}
	})

	// The defaults are for a STANDALONE sweep. Riding along inside a larger scan
	// they would silently retune the transport and redirect policy for every
	// other phase in that scan.
	t.Run("not applied when the probe rides along in a wider scan", func(t *testing.T) {
		opts := &types.Options{OnlyPhase: "probe,discovery"}
		if err := ApplyNativePhaseSelection(opts, nil); err != nil {
			t.Fatalf("ApplyNativePhaseSelection: %v", err)
		}
		if !opts.ProbeEnabled {
			t.Fatal("ProbeEnabled = false")
		}
		if opts.RecordRedirectChain || opts.RedirectMode != "" || opts.TransportProfile != "" || opts.NoWafPacing {
			t.Errorf("probe-only defaults leaked into a multi-phase scan: chain=%v mode=%q profile=%q nopacing=%v",
				opts.RecordRedirectChain, opts.RedirectMode, opts.TransportProfile, opts.NoWafPacing)
		}
	})

	t.Run("not applied to a scan that never selected the probe", func(t *testing.T) {
		opts := &types.Options{OnlyPhase: "discovery"}
		if err := ApplyNativePhaseSelection(opts, nil); err != nil {
			t.Fatalf("ApplyNativePhaseSelection: %v", err)
		}
		if opts.NoWafPacing || opts.TransportProfile != "" {
			t.Error("probe defaults applied to a non-probe run")
		}
	})
}

// Infrastructure that only shapes target traffic must not be built for a plan
// that never contacts the target; see SendsTargetTraffic for what that cost.
func TestNativeScanPlanSendsTargetTraffic(t *testing.T) {
	// Derived from a real plan rather than hand-built steps, so the SkipsTarget
	// attribute comes from the phase table itself. A literal here would pass
	// while the table said something else, which is the drift this attribute was
	// moved onto the table to prevent.
	enabledOnly := func(phases ...NativePhase) NativeScanPlan {
		reference := BuildNativeScanPlan(&types.Options{})
		steps := make([]NativePhaseStep, 0, len(reference.Steps))
		for _, step := range reference.Steps {
			step.Enabled = slices.Contains(phases, step.Phase)
			steps = append(steps, step)
		}
		return NativeScanPlan{Steps: steps}
	}

	t.Run("external-harvest alone never contacts the target", func(t *testing.T) {
		assert.False(t, enabledOnly(PhaseExternalHarvest).SendsTargetTraffic())
	})

	t.Run("nothing enabled", func(t *testing.T) {
		assert.False(t, enabledOnly().SendsTargetTraffic())
	})

	// Every other phase reaches the target directly or through the shared
	// requester, so each one on its own has to keep sessions and hooks.
	for _, phase := range []NativePhase{
		PhaseHeuristicsCheck, PhasePortSweep, PhaseSpidering, PhaseProbe,
		PhaseDiscovery, PhaseTargetedReSpider, PhaseSeed,
		PhaseDynamicAssessment, PhaseKnownIssueScan,
	} {
		t.Run(string(phase)+" reaches the target", func(t *testing.T) {
			assert.True(t, enabledOnly(phase).SendsTargetTraffic())
		})
	}

	t.Run("external-harvest alongside a scanning phase still counts", func(t *testing.T) {
		assert.True(t, enabledOnly(PhaseExternalHarvest, PhaseProbe).SendsTargetTraffic())
	})

	// A disabled step must not count, or --only external-harvest would be
	// indistinguishable from a full plan.
	t.Run("disabled steps are ignored", func(t *testing.T) {
		plan := NativeScanPlan{Steps: []NativePhaseStep{
			{Phase: PhaseProbe, Enabled: false},
			{Phase: PhaseExternalHarvest, Enabled: true, SkipsTarget: true},
		}}
		assert.False(t, plan.SendsTargetTraffic())
	})

	// The attribute has to be declared on the step, not inferred: a plan that
	// forgets it must fail closed (build the infrastructure) rather than skip
	// session hydration for a phase that does reach the target.
	t.Run("an unmarked phase counts as reaching the target", func(t *testing.T) {
		plan := NativeScanPlan{Steps: []NativePhaseStep{
			{Phase: PhaseExternalHarvest, Enabled: true},
		}}
		assert.True(t, plan.SendsTargetTraffic())
	})
}
