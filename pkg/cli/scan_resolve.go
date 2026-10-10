package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// explicitScanPace reports which pace knobs the operator typed on this command.
//
// globalChanged, not cmd.Flags().Changed, for the three pace dials: pflag marks
// a flag Changed when only its PHASE-QUALIFIED form was typed, and a per-phase
// value is not an operator overruling the strategy's invocation-wide ceiling.
func explicitScanPace(cmd *cobra.Command) runner.ExplicitPace {
	changed := func(name string) bool {
		f := cmd.Flags().Lookup(name)
		return f != nil && f.Changed
	}
	return runner.ExplicitPace{
		Concurrency:          concurrencyKnob.globalChanged(),
		RateLimit:            rateLimitKnob.globalChanged(),
		MaxPerHost:           maxPerHostKnob.globalChanged(),
		ExternalHarvest:      changed("external-harvest"),
		DiscoverMaxDuration:  changed("discover-max-time"),
		SpideringMaxDuration: changed("spider-max-time"),
		MaxRequests:          changed("max-requests"),
		MaxRequestsPerHost:   changed("max-requests-per-host"),
	}
}

// resolveNativeScanOptions runs the shared scan-options resolution for the scan
// command (the ordering contract is documented in runner/strategy_apply.go):
// intensity/profile → settings overrides → strategy (explicit rate limit,
// phases, pace ceiling, heuristics) → --only/--skip → per-phase qualifiers →
// scanning_pace fold. REST and the agent launcher call the same runner
// functions, so one request resolves to one pace on every entry point.
//
// It returns the resolved strategy name ("" when none applied). Nothing here
// writes files or touches the network beyond reading a named profile.
func resolveNativeScanOptions(cmd *cobra.Command, settings *config.Settings, opts *types.Options) (string, error) {
	explicit := explicitScanPace(cmd)

	profileReq := runner.ProfileRequest{Profile: globalScanningProfile}
	if cmd.Flags().Changed("intensity") {
		profileReq.Intensity = globalIntensity
	}
	profilePath, err := runner.ApplyIntensityAndProfile(settings, opts, profileReq)
	if err != nil {
		return "", err
	}
	if profilePath != "" {
		zap.L().Info("Applied scanning profile", zap.String("profile", opts.ScanningProfile), zap.String("path", profilePath))
	}

	if cmd.Flags().Changed("scanning-max-duration") && globalScanningMaxDuration > 0 {
		opts.ScanMaxDuration = globalScanningMaxDuration
	}
	runner.ApplyScanSettingOverrides(settings, opts)

	strategy, err := runner.ApplyScanStrategy(settings, opts, runner.StrategyRequest{
		Name:            globalStrategy,
		HeuristicsCheck: globalHeuristicsCheck,
		SkipHeuristics:  globalSkipHeuristics,
		Explicit:        explicit,
	})
	if err != nil {
		if errors.Is(err, runner.ErrUnknownStrategy) {
			return "", asUsageError(err)
		}
		return "", err
	}
	if strategy.Name != "" {
		zap.L().Debug("Applied scanning strategy",
			zap.String("strategy", strategy.Name),
			zap.Bool("external_harvest", opts.ExternalHarvestEnabled))
	}

	// A hand-picked module selection (--module-id / -m) implies a targeted,
	// low-noise scan, so auto-skip the broad known-issue-scan pass before phase
	// selection resolves it. Must run after the strategy sets KnownIssueScanEnabled
	// and before ApplyNativePhaseSelection consumes SkipPhases.
	autoSkipKnownIssueScanForModuleSelection(opts)

	// Before ApplyNativePhaseSelection: it applies the probe phase's own
	// defaults, and needs to know whether --record-redirect-chain was typed.
	if err := applyProbeFlags(opts, cmd); err != nil {
		return "", err
	}
	if err := runner.ApplyNativePhaseSelection(opts, func(enabled bool) {
		settings.DynamicAssessment.Extensions.Enabled = enabled
	}); err != nil {
		return "", err
	}
	warnInertProbeFlags(opts, cmd)
	if err := applyExportScope(opts); err != nil {
		return "", err
	}
	if opts.OnlyPhase != "" {
		zap.L().Info("Phase isolation active", zap.String("only", opts.OnlyPhase))
	}
	if len(opts.SkipPhases) > 0 {
		zap.L().Info("Phases skipped", zap.Strings("skip", opts.SkipPhases))
	}

	// Per-phase pace qualifiers (`--rate-limit known-issue-scan=20`) land in the
	// matching scanning_pace section, so ResolvePhase stays the one place
	// per-phase pace is merged. Applied after the phase selection is settled so a
	// qualifier naming a phase this run skips can be reported.
	applyPhasePaceOverrides(settings, opts)

	if err := runner.ApplyScanPace(settings, opts, explicit); err != nil {
		return "", err
	}
	return strategy.Name, nil
}
