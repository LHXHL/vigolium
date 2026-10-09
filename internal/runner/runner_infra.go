package runner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"go.uber.org/zap"
)

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
//
// ctx is the scan context (already carrying --scanning-max-duration when set),
// threaded in so the one piece of setup that talks to the network — the session
// login flows — is cancellable and bounded like everything else. Nothing else
// here blocks: the rest is in-process construction.
func (r *Runner) buildInfrastructure(ctx context.Context, plan NativeScanPlan) (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-uuid
	scanUUID := r.options.ScanUUID
	if scanUUID == "" {
		scanUUID = uuid.New().String()
		r.options.ScanUUID = scanUUID
	}

	infra := &phaseInfra{
		scanUUID: scanUUID,
	}

	// If SharedInfra is available, reuse its components instead of building fresh
	if r.sharedInfra != nil {
		// Borrowed, not owned — phaseInfra.Close must leave these to the owner.
		infra.borrowedInfra = true
		infra.httpRequester = r.sharedInfra.HTTPRequester
		infra.scopeMatcher = r.sharedInfra.ScopeMatcher
		infra.hostLimiter = r.sharedInfra.HostLimiter
		infra.svc = r.sharedInfra.Services
		infra.jsEngine = r.sharedInfra.JSEngine
		infra.hookChain = r.sharedInfra.HookChain
		// Still need to initialize sessions
		if err := r.initSessions(ctx, infra); err != nil {
			if len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0 {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			// Continuing unauthenticated. Recorded so the assessment phases can
			// say so instead of letting a wall of 401s read as an open app.
			infra.authFailureReason = authFailureReason(ctx, err)
			zap.L().Warn("Failed to initialize sessions", zap.Error(err))
		}
		return infra, nil
	}

	// Create notifier with backends. Each backend is gated by the
	// notify.provider selector — empty means "all", a specific value
	// activates only that channel.
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend
		notifyCfg := &r.settings.Notify

		// Telegram backend (from settings or env). Construction no longer
		// contacts Telegram (see telegram.NewClient), so this cannot delay the
		// first phase; what it can still report is a malformed token or chat id,
		// which used to be dropped on the floor — an operator who enabled
		// notifications and mistyped the config got no notifications and no
		// explanation, matching the Discord branch below.
		if notifyCfg.IsProviderActive(config.NotifyProviderTelegram) {
			tgOpts := r.buildTelegramOptions()
			if tg, err := telegram.NewBackend(tgOpts...); err == nil {
				backends = append(backends, tg)
				zap.L().Info("[Notify] Telegram backend enabled")
			} else {
				zap.L().Warn("[Notify] Failed to create Telegram backend", zap.Error(err))
			}
		}

		// Discord backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderDiscord) {
			webhookURL := notifyCfg.Discord.WebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
			}
			if webhookURL != "" {
				if dc, err := discord.NewBackend(webhookURL); err == nil {
					backends = append(backends, dc)
					zap.L().Info("[Notify] Discord backend enabled")
				} else {
					zap.L().Warn("[Notify] Failed to create Discord backend", zap.Error(err))
				}
			}
		}

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: notifyCfg.Severities,
			})
		}
	}

	// Create runtime services
	svc := &services.Services{
		Options:      r.options,
		Notifier:     infra.notifier,
		DedupManager: r.dedupManager,
		RateLimiter:  buildScanRateLimiter(effectiveRateLimit(r.options)),
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrors.New(
			r.options.MaxHostError,
			hosterrors.DefaultMaxHostsCount,
			[]string{},
		)
		cache.SetVerbose(r.options.Verbose)
		svc.HostErrors = cache
	}

	// Create HostLimiter for per-host concurrency control
	maxPerHost := r.options.MaxPerHost
	if !r.options.MaxPerHostExplicitlySet {
		// Not chosen on the CLI: let newHostLimiter apply the common
		// scanning_pace value, then its own floor.
		maxPerHost = 0
	}
	hostLimiter := newHostLimiter(maxPerHost, r.settings, r.options.NoWafPacing)
	svc.HostLimiter = hostLimiter
	infra.hostLimiter = hostLimiter
	infra.svc = svc

	httpRequester, err := http.NewRequester(r.options, svc)
	if err != nil {
		infra.Close()
		return nil, errors.Wrap(err, "could not create http requester")
	}
	infra.httpRequester = httpRequester

	// Create scope matcher from settings, passing CLI targets for cli_origin_mode filtering
	if r.settings != nil {
		infra.scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.options.Targets...)
	}

	// Phases that never contact the target are unaffected by session headers and
	// request hooks, so neither is built for them. See SendsTargetTraffic for why
	// this is not merely about setup cost.
	reachesTarget := plan.SendsTargetTraffic()

	// Initialize JS extension engine
	if reachesTarget && r.settings != nil && r.settings.DynamicAssessment.Extensions.Enabled {
		jsEngineOpts := &jsext.EngineOptions{
			ScanUUID:   r.options.ScanUUID,
			Repository: r.repository,
			LLMClient:  extensionLLMClient(r.settings),
		}
		if r.settings != nil {
			scopeCfg := r.settings.Scope
			jsEngineOpts.ScopeConfig = &scopeCfg
			// The same matcher, from the same settings and the same targets, as
			// the one built above - so share it rather than paying for a second.
			jsEngineOpts.ScopeMatcher = infra.scopeMatcher
		}
		jsEngine, err := jsext.NewEngine(&r.settings.DynamicAssessment.Extensions, httpRequester, jsEngineOpts)
		if err != nil {
			zap.L().Warn("Failed to initialize JS extensions", zap.Error(err))
		} else {
			// Create hook chain if hooks are defined
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.hookChain = jsext.NewHookChain(preHooks, postHooks)
				zap.L().Info("JS hooks loaded",
					zap.Int("pre_hooks", len(preHooks)),
					zap.Int("post_hooks", len(postHooks)))
			}
			// Store the engine in infra for module resolution
			infra.jsEngine = jsEngine
		}
	}

	// Initialize multi-session support for IDOR/BOLA testing. Skipped when no
	// enabled phase will reach the target: see reachesTarget above.
	if reachesTarget {
		if err := r.initSessions(ctx, infra); err != nil {
			// If the user explicitly configured sessions, surface the error clearly
			hasCLIAuth := len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0
			if hasCLIAuth && !r.options.AuthBestEffort {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			// Continuing unauthenticated. Recorded so the assessment phases can
			// say so instead of letting a wall of 401s read as an open app.
			infra.authFailureReason = authFailureReason(ctx, err)
			zap.L().Warn("Failed to initialize sessions, continuing without session support", zap.Error(err))
		}
	}

	return infra, nil
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
// phaseDeadline derives a phase-scoped context bounded by maxDuration so a phase
// cannot run past its configured scanning_pace max_duration. It is the single
// chokepoint for the "wrap the WHOLE phase, not just one leg" invariant that
// known-issue-scan once regressed on (the Nuclei leg was bounded but the
// secret-scan leg ran on the raw ctx). When maxDuration <= 0 the phase is
// unbounded: the parent ctx is returned unchanged with a no-op cancel so callers
// can always `defer cancel()`. When the parent already has an earlier deadline
// (e.g. the overall scan budget), context.WithTimeout keeps that earlier
// deadline, so a phase can never extend the scan.
func phaseDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	if maxDuration <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, maxDuration)
}
