package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// stderrCaptureActive guards the process-global os.Stderr redirection used for
// raw-stderr scan-log capture. Only the scan that wins the claim redirects
// os.Stderr; concurrent scans skip capture so they can't restore/close each
// other's descriptors.
var stderrCaptureActive atomic.Bool

// cursorFlushBudget bounds the post-round cursor checkpoint. It runs on a
// context detached from the phase's, so it needs a bound of its own; ten seconds
// is generous for one UPDATE and short enough that a wedged database delays
// teardown by a visible-but-tolerable amount rather than hanging it.
const cursorFlushBudget = 10 * time.Second

// teeDrainTimeout bounds the wait for the stderr-capture reader to finish after
// the write end is closed. The healthy path takes microseconds and never
// reaches it; the timeout exists only so a wedged reader cannot hang a scan's
// teardown, at the cost of a few trailing log lines.
const teeDrainTimeout = 2 * time.Second

// RunNativeScan orchestrates the native scan plan:
//
//	HeuristicsCheck   — optional root-page probe to optimize downstream phase selection
//	ExternalHarvest   — harvest URLs from external intelligence sources (opt-in)
//	HarvestProbe      — drop dead/404 harvested URLs before a later phase scans them
//	Spidering         — browser-based crawling (opt-in)
//	Discovery         — ingest all input + deparos content discovery into DB (no modules)
//	Seed              — ingest CLI targets when discovery is skipped but DB-backed phases still need records
//	ParamMining       — discover hidden parameters on recorded endpoints (deep / --param-mining)
//	KnownIssueScan    — nuclei + secret scan (opt-in via --known-issue-scan)
//	DynamicAssessment — modules + extensions scan DB records
func (r *Runner) RunNativeScan() (err error) {
	defer close(r.done)
	ctx := r.ctx

	// A Runner is reused across agent rescans, so the phase ledger starts empty
	// here rather than at construction — otherwise the second run's scan row
	// would carry the first run's curtailment.
	r.scanOutcome.reset()
	r.preflight = nil

	// Total scan budget: when --scanning-max-duration is set, bound the WHOLE scan
	// (all phases combined). Each phase wraps this ctx with its own per-phase
	// deadline via phaseDeadline, which keeps the earlier deadline — so phases can
	// share and never exceed this total budget. End-of-scan DB bookkeeping below
	// stays on r.ctx (the un-bounded parent) so the scan record is still finalized
	// after the budget fires.
	if r.options.ScanMaxDuration > 0 {
		zap.L().Info("Total scan budget active — the whole scan is bounded by --scanning-max-duration; phases share it and remaining phases are skipped once it elapses",
			zap.Duration("scan_max_duration", r.options.ScanMaxDuration))
		var totalCancel context.CancelFunc
		ctx, totalCancel = context.WithTimeout(ctx, r.options.ScanMaxDuration)
		defer totalCancel()
	}
	// Request budget (--max-requests / --max-requests-per-host): built before
	// the infrastructure, whose egress gate enforces it, and bounding the same
	// ctx the phases run under, which it cancels when the scan-wide limit runs
	// out. See armRequestBudget.
	ctx, stopRequestBudget := r.armRequestBudget(ctx)
	defer stopRequestBudget()
	// A session lost mid-scan under reauth.on_failure: abort cancels this ctx
	// with an *AuthLostError; the phases wind down as for a budget, attributed
	// to auth_lost, and the run returns the error. See armAuthAbort.
	ctx, stopAuthAbort := r.armAuthAbort(ctx)
	defer stopAuthAbort()

	plan := BuildNativeScanPlan(r.options)

	// Scope admission over the CLI targets, before anything is built: when
	// scope refuses every target the run sends nothing, so it must not build
	// the infrastructure that does (session logins, OAST registration). An
	// empty plan is how buildInfrastructure is told; the run fails below, once
	// the scan row exists to say why.
	admission := r.targetAdmission()
	if admission != nil && admission.NoneAdmitted() {
		plan = NativeScanPlan{}
	}

	infra, err := r.buildInfrastructure(ctx, plan)
	if err != nil {
		return err
	}
	defer infra.Close()

	// Warn the operator (once per host) when the edge WAF/CDN starts filtering
	// scan traffic, across all phases that share this requester.
	r.attachWAFBlockNotifier(infra.httpRequester)
	// Proactively pace a host the first time an earlier phase reveals it is behind a
	// CDN/WAF edge, so the active phase does not burst the edge into a rate-based
	// block before the high-value probes run. Hangs off the shared host limiter (not a
	// single requester), so the notice fires once per host regardless of which
	// requester — heuristics, auth prep, discovery — first tripped the pre-arm.
	r.attachWAFPacingNotifier(infra.hostLimiter)
	// Route every finding the writer emits onto the machine event stream. One
	// seam rather than one per OnResult callback; see attachEventObserver.
	r.attachEventObserver()

	// Initialize scan logger (must happen before printScanConfig so the tee captures it)
	r.scanLogger = database.NewScanLogger(r.repository, infra.scanUUID)
	r.scanLogger.StartBatcher()
	defer r.scanLogger.Close()

	// Create scan record in the database so every scan is tracked with its lifecycle.
	// Skip when ScanOnReceive or ManagedScanRecord — the server already created the
	// scan record and owns its pending/queued/running transitions.
	if r.repository != nil && !r.options.ScanOnReceive && !r.options.ManagedScanRecord {
		target := strings.Join(r.options.Targets, ", ")
		scan := &database.Scan{
			UUID:            infra.scanUUID,
			ProjectUUID:     r.options.ProjectUUID,
			Name:            "cli-scan",
			Status:          "running",
			Target:          target,
			Threads:         r.options.Concurrency,
			ScopeOriginMode: r.resolvedScopeOriginMode(),
			ScanSource:      "cli",
			ScanMode:        "full",
			StartedAt:       time.Now(),
		}
		if err := r.repository.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}
	// Stamp the resolved scope mode on the row, whoever created it — there are ten
	// scan-creation sites and only the runner knows the settings the matcher will
	// actually be built from.
	r.persistScopeOriginMode(ctx, infra.scanUUID)
	// Liveness heartbeat, always on (status.json + the row's heartbeat
	// columns). Finish is registered BEFORE the finalizer so it runs AFTER it
	// (defers are LIFO): status.json only states a terminal status once the
	// row does. The finalizer itself calls Stop first, which writes the final
	// total_requests before the row is completed.
	liveness := r.startLiveness(infra, plan)
	defer func() {
		liveness.Finish(r.terminalSessionStatus(err))
		r.liveness.Store(nil)
	}()
	if r.repository != nil {
		defer func() {
			// Terminal status, most-truthful first: a returned error (including a
			// recovered panic — the recovery defer below sets err, and runs before
			// this one since it is registered later) marks the scan failed;
			// otherwise a cancelled run context marks it cancelled; otherwise it
			// completed cleanly.
			var errMsg string
			switch {
			case err != nil:
				errMsg = err.Error()
			case r.ctx.Err() != nil:
				errMsg = "cancelled"
			}
			// Finalize on a detached, bounded context: r.ctx is already cancelled on
			// a stop/Ctrl-C, which would fail this write and leave the row stuck at
			// "running". WithoutCancel keeps values (project/tenant) but not the
			// cancellation, so the terminal status always lands. This makes the
			// runner the single finalization owner — the server no longer overwrites.
			finalCtx, finalCancel := context.WithTimeout(context.WithoutCancel(r.ctx), 30*time.Second)
			defer finalCancel()
			liveness.Stop(finalCtx)
			// WithOutcome, not CompleteScan: the runner is the only component that
			// saw every phase, so it is the only one that can say whether the run
			// actually covered its input. Everything else writes "unknown".
			if completeErr := r.repository.CompleteScanWithOutcome(finalCtx, infra.scanUUID, errMsg, r.Completion()); completeErr != nil {
				zap.L().Warn("Failed to complete scan record", zap.Error(completeErr))
			}
			r.finalized.Store(true)
		}()
	}

	// The preflight verdict, recorded whether or not anything was refused so
	// the row always carries the target tally. A scope that refused every
	// target ends the run here: nothing was sent, and the finalizer above
	// stores the row failed with stop_reason no_targets_in_scope. Otherwise the
	// outcome is appended once the reachability check below has filled it in.
	var preflightOutcome *database.PhaseOutcome
	if admission != nil {
		pre := admissionOutcome(*admission)
		preflightOutcome = &pre
		for _, v := range admission.Rejected {
			r.scanLogger.Warn(string(PhasePreflight), fmt.Sprintf("target %s rejected by scope (%s)", v.Target, v.Rule))
		}
		if admission.NoneAdmitted() {
			r.scanOutcome.append(pre)
			r.scanOutcome.setStopReason(database.ReasonNoTargetsInScope)
			rejected := &TargetsRejectedError{Admission: *admission}
			r.scanLogger.Error(string(PhasePreflight), rejected.Error())
			return rejected
		}
	}

	// Set up TeeWriter to capture raw stderr output as trace-level scan logs.
	//
	// This redirects the PROCESS-GLOBAL os.Stderr to a pipe, so only one scan may
	// own the capture at a time: two concurrent scans (server mode) would otherwise
	// restore or close each other's descriptors and corrupt process-wide stderr.
	// A single-owner claim keeps the common single-scan (CLI) case fully captured
	// while a concurrent secondary scan simply skips raw capture rather than racing.
	if r.repository != nil && stderrCaptureActive.CompareAndSwap(false, true) {
		defer stderrCaptureActive.Store(false)
		origStderr := os.Stderr
		// Optionally mirror raw console output to ~/.vigolium/native-sessions/{uuid}/run.log.
		var sessionLogFile *os.File
		var teeInner io.Writer = origStderr
		if r.settings != nil && r.settings.ScanningStrategy.ScanLogs.IsPersistLogsEnabled() {
			sessionDir := filepath.Join(r.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), infra.scanUUID)
			if mkErr := os.MkdirAll(sessionDir, 0o755); mkErr == nil {
				logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
				if f, openErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); openErr == nil {
					sessionLogFile = f
					r.sessionLogFile = f
					teeInner = io.MultiWriter(origStderr, sessionLogFile)
				} else {
					zap.L().Warn("Failed to open native session log file", zap.String("path", logPath), zap.Error(openErr))
				}
			} else {
				zap.L().Warn("Failed to create native session directory", zap.String("path", sessionDir), zap.Error(mkErr))
			}
		}
		r.teeWriter = newTeeWriter(teeInner, r.scanLogger)
		pr, pw, err := os.Pipe()
		if err == nil {
			os.Stderr = pw
			// Goroutine reads from the pipe and writes through the tee, and
			// closes drained when the pipe reports EOF.
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				buf := make([]byte, 4096)
				for {
					n, readErr := pr.Read(buf)
					if n > 0 {
						_, _ = r.teeWriter.Write(buf[:n])
					}
					if readErr != nil {
						break
					}
				}
			}()
			defer func() {
				// Closing the write end is what ends the reader's loop, so wait
				// for the goroutine to say it is done rather than guessing how
				// long that takes. The old blind 50ms sleep was both a floor on
				// every scan's teardown - visible on a probe that finishes in
				// under a fifth of a second - and no guarantee at all on a busy
				// machine, where the drain could still be unfinished when the
				// descriptor was yanked. The timeout only bounds a reader that
				// is stuck, which costs at most a few trailing log lines.
				_ = pw.Close()
				select {
				case <-drained:
				case <-time.After(teeDrainTimeout):
					zap.L().Warn("stderr capture did not drain within the timeout; some trace logs may be missing")
				}
				_ = pr.Close()
				os.Stderr = origStderr
				r.teeWriter.Flush()
				if sessionLogFile != nil {
					r.sessionLogMu.Lock()
					r.sessionLogFile = nil
					r.sessionLogMu.Unlock()
					_ = sessionLogFile.Close()
				}
			}()
		} else if sessionLogFile != nil {
			// Pipe setup failed; still close the log file we opened.
			defer func() { _ = sessionLogFile.Close() }()
		}
	}

	// Print scan configuration summary
	r.printScanConfig()

	r.scanLogger.Info("", "scan started")

	// Log scan configuration snapshot as structured metadata.
	r.logConfigSnapshot()

	// Banner the end of the scan lifecycle on stderr so operators see at a glance
	// when scanning wraps up, with wall-clock duration and finding count.
	// Suppressed by --silent. The scan kickoff is already announced by the Scan ID
	// line in the configuration banner above, so there is no separate "started"
	// marker here.
	scanStartedAt := time.Now()
	if !r.options.Silent {
		defer func() {
			// Detached, like the completion defer: on Ctrl-C the run context is
			// already cancelled, and a read on it fails and drops the count.
			finalCtx, finalCancel := context.WithTimeout(context.WithoutCancel(r.ctx), 10*time.Second)
			defer finalCancel()
			r.printFinishedBanner(finalCtx, os.Stderr, infra.scanUUID, time.Since(scanStartedAt))
		}()
	}

	// Panic recovery with notification. Sets the named return so the panic
	// surfaces as a scan error instead of being swallowed into a nil return that
	// the finalizer (and the server) would record as a successful scan.
	defer func() {
		if rec := recover(); rec != nil {
			stack := make([]byte, 4096)
			length := goruntime.Stack(stack, false)
			stackTrace := string(stack[:length])

			errorMessage := fmt.Sprintf(
				"Recovered from panic in runner execution: %+v\nStack Trace:\n%s",
				rec,
				stackTrace,
			)
			zap.L().Error(errorMessage)
			r.scanLogger.Error("", "panic recovered: "+fmt.Sprintf("%+v", rec))
			if infra.notifier != nil {
				_ = infra.notifier.SendRaw(errorMessage)
			}
			err = errors.Errorf("panic recovered in runner execution: %+v", rec)
		}
	}()

	// Final project-wide finding grouping, on every exit path (success, phase error,
	// budget cutoff, panic) via defer, so findings on redirected / third-party hosts —
	// and any scan that skipped known-issue-scan — still collapse per-asset rows before
	// results are read. Registered here (after infra/scanLogger exist) so it runs first
	// among the teardown defers: while stderr is still tee'd to the run log and before
	// the finished-banner reads the finding count. Idempotent when prior passes already
	// covered everything; see finalizeFindingGrouping.
	defer r.finalizeFindingGrouping()

	// Reachability preflight: one GET per admitted CLI target. None answered
	// ends the run here (stop_reason no_targets_reachable; the CLI exits 1 with
	// that error.code); some answered marks the scan partial with
	// targets_unreachable and keeps every target in the plan.
	if preflightOutcome != nil {
		var preErr error
		if r.preflightApplies(plan) {
			preErr = r.runPreflight(ctx, infra, admission.Admitted, preflightOutcome)
		}
		r.scanOutcome.append(*preflightOutcome)
		if preErr != nil {
			return preErr
		}
	}

	// Full-scan-on-receive: loop waiting for new records, then run all phases
	// on just the new batch. Each iteration swaps r.inputSource to a one-shot
	// DB source so Discovery processes only newly arrived records.
	if r.options.FullNativeScanOnReceive && r.repository != nil {
		for ctx.Err() == nil {
			if err := r.waitForNewRecords(ctx, infra.scanUUID, 2*time.Second); err != nil {
				break
			}
			r.inputSource = database.NewOneShotDBInputSource(r.repository.DB(), r.repository, infra.scanUUID)
			for i, step := range plan.Steps {
				if !step.Enabled {
					continue
				}
				if ctx.Err() != nil {
					r.recordSkippedSteps(plan.Steps[i:], scanStopReason(ctx, r.ctx))
					break
				}
				if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
					zap.L().Error("Full-scan-on-receive: phase error", zap.Error(err))
					break
				}
			}
		}
		r.scanLogger.Info("", "scan finished")
		return nil
	}

	for i, step := range plan.Steps {
		if !step.Enabled {
			continue
		}
		// Stop launching phases once the total scan budget (--scanning-max-duration)
		// has elapsed. Mirrors the full-scan-on-receive loop guard above so a
		// curtailed scan ends cleanly instead of starting phases that would
		// immediately abort on the already-expired ctx.
		if ctx.Err() != nil {
			zap.L().Warn("Scan stopped (budget or cancellation); skipping remaining phases",
				zap.String("phase", string(step.Phase)),
				zap.String("reason", scanStopReason(ctx, r.ctx)))
			// Record the phases that never ran. Without this the scan row shows
			// outcomes only for the phases that happened to start, which reads
			// exactly like a scan whose plan was that short to begin with.
			r.recordSkippedSteps(plan.Steps[i:], scanStopReason(ctx, r.ctx))
			break
		}
		if err := r.executeNativePhase(ctx, infra, step.Phase); err != nil {
			return err
		}
	}
	if lost := authLostCause(ctx); lost != nil {
		return lost
	}
	if r.options.SkipIngestion && !r.options.KnownIssueScanEnabled && r.options.SkipDynamicAssessment {
		zap.L().Info("Discovery skipped, no downstream phases need DB records")
		r.scanLogger.Info("discovery", "skipped, no downstream phases need DB records")
	}
	if r.options.SkipDynamicAssessment {
		zap.L().Info("Dynamic-assessment skipped by scanning strategy")
		r.scanLogger.Info("dynamic-assessment", "skipped by scanning strategy")
	}

	r.scanLogger.Info("", "scan finished")
	return nil
}

// printFinishedBanner writes the "Scan finished" line: the scan id, wall-clock
// duration, the scan's finding count, and the partial-coverage suffix.
//
// The count comes from repository.ScanFindingTotal — the findings table, not the
// scan row — which is the same helper the CLI's completion summary prints. The
// row was the bug: this banner runs before the completion defer finalizes it
// (defers are LIFO, and this one is registered later so it stays inside the
// stderr capture), so total_findings still held its pre-finalize 0 and the
// banner said "findings: 0" a line above the summary's "5 issues found". The
// table is already final here: finding grouping has run, and nothing between
// this defer and finalization writes findings.
//
// With no repository the line carries the duration only; on a failed count it
// omits the count rather than print a zero it does not know to be true.
func (r *Runner) printFinishedBanner(ctx context.Context, w io.Writer, scanUUID string, duration time.Duration) {
	findingSummary := ""
	if r.repository != nil {
		if total, _, err := r.repository.ScanFindingTotal(ctx, scanUUID); err == nil {
			findingSummary = fmt.Sprintf(", findings: %d", total)
		} else {
			zap.L().Debug("Scan finished banner: finding count unavailable", zap.Error(err))
		}
	}
	fmt.Fprintf(w, "  %s Scan finished %s %s%s\n",
		terminal.SuccessSymbol(),
		terminal.BoldCyan(scanUUID),
		terminal.Gray(fmt.Sprintf("duration: %s%s", fmtDuration(duration), findingSummary)),
		partialBannerSuffix(r.Completion()))
}

func (r *Runner) executeNativePhase(ctx context.Context, infra *phaseInfra, phase NativePhase) (err error) {
	// One tracker per phase, wrapped around the whole switch rather than
	// duplicated into its nine arms: the arms disagree about what an error means
	// (most log and continue, discovery and seed return), and a per-arm emitter
	// would have to restate that disagreement nine times. Here the tracker sees
	// the same outcome the caller does.
	//
	// r.currentPhase is set so the module result callbacks — which run on worker
	// goroutines with no idea which phase they belong to — can count a finding
	// against the phase that produced it.
	tracker := r.beginPhase(ctx, string(phase), infra.httpRequester)
	r.currentPhase.Store(tracker)
	// Account the phase's logged-out traffic (responses_while_logged_out,
	// auth_lost) when it finishes.
	infra.sessions.trackPhase(tracker)
	// Phases that run core.Executor report done/total off every executor they
	// start, however deep in the phase it is built (dynamic assessment builds
	// one per feedback round). A context value rather than a parameter so the
	// executor sites need not know the event stream exists. Values only: the
	// derived context cancels exactly as ctx does, so finish reads the same Err.
	if unit, ok := executorProgressUnit[phase]; ok {
		tracker.setProgress(unit, tracker.executorProgress)
		ctx = core.WithExecutorObserver(ctx, tracker.observeExecutor)
	}
	liveness := r.liveness.Load()
	liveness.PhaseStarted(string(phase))
	defer func() {
		r.currentPhase.Store((*phaseTracker)(nil))
		r.scanOutcome.append(tracker.finish(ctx, err))
		liveness.PhaseEnded(string(phase), tracker.extraSentSoFar())
	}()

	switch phase {
	case PhaseHeuristicsCheck:
		r.setPhaseTag("heuristics")
		r.scanLogger.Info("heuristics", "phase started")
		results, err := r.runHeuristicsCheckPhase(ctx, infra)
		if err != nil {
			zap.L().Error("HeuristicsCheck phase failed", zap.Error(err))
			r.scanLogger.Error("heuristics", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.heuristicsResults = results
			r.scanLogger.Info("heuristics", "phase completed")
		}
	case PhasePortSweep:
		r.setPhaseTag("port-sweep")
		r.scanLogger.Info("port-sweep", "phase started")
		if err := r.runPortSweepPhase(ctx, infra); err != nil {
			zap.L().Error("PortSweep phase failed", zap.Error(err))
			r.scanLogger.Error("port-sweep", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("port-sweep", "phase completed")
		}
	case PhaseExternalHarvest:
		r.setPhaseTag("harvest")
		r.scanLogger.Info("harvest", "phase started")
		if err := r.runExternalHarvestPhase(ctx, infra); err != nil {
			zap.L().Error("ExternalHarvest phase failed", zap.Error(err))
			r.scanLogger.Error("harvest", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("harvest", "phase completed")
		}
	case PhaseHarvestProbe:
		r.setPhaseTag("harvest-probe")
		r.scanLogger.Info("harvest-probe", "phase started")
		if err := r.runHarvestProbePhase(ctx, infra); err != nil {
			zap.L().Error("HarvestProbe phase failed", zap.Error(err))
			r.scanLogger.Error("harvest-probe", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("harvest-probe", "phase completed")
		}
	case PhaseSpidering:
		r.setPhaseTag("spider")
		r.scanLogger.Info("spidering", "phase started")
		if err := r.runSpideringPhase(ctx, infra); err != nil {
			zap.L().Error("Spidering phase failed", zap.Error(err))
			r.scanLogger.Error("spidering", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("spidering", "phase completed")
		}
	case PhaseProbe:
		r.setPhaseTag("probe")
		r.scanLogger.Info("probe", "phase started")
		if err := r.runProbePhase(ctx, infra); err != nil {
			zap.L().Error("Probe phase failed", zap.Error(err))
			r.scanLogger.Error("probe", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("probe", "phase completed")
		}
	case PhaseDiscovery:
		r.setPhaseTag("discovery")
		r.scanLogger.Info("discovery", "phase started")
		if err := r.runDiscoveryPhase(ctx, infra); err != nil {
			r.scanLogger.Error("discovery", "phase failed: "+err.Error())
			// No noteError here: this error is RETURNED, so it ends the scan and
			// rides out on scan.finished. The tracker records it once, in finish.
			return fmt.Errorf("discovery phase failed: %w", err)
		}
		r.scanLogger.Info("discovery", "phase completed")
		if r.repository != nil {
			r.cleanupDeparosRecords(ctx)
		}
	case PhaseTargetedReSpider:
		r.setPhaseTag("respider")
		r.scanLogger.Info("respider", "phase started")
		if err := r.runTargetedReSpiderPhase(ctx, infra); err != nil {
			zap.L().Error("Targeted re-spider phase failed", zap.Error(err))
			r.scanLogger.Error("respider", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("respider", "phase completed")
		}
	case PhaseParamMining:
		r.setPhaseTag("param-mining")
		r.scanLogger.Info("param-mining", "phase started")
		if err := r.runParamMiningPhase(ctx, infra); err != nil {
			zap.L().Error("ParamMining phase failed", zap.Error(err))
			r.scanLogger.Error("param-mining", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("param-mining", "phase completed")
		}
	case PhaseSeed:
		r.setPhaseTag("seed")
		r.scanLogger.Info("seed", "seeding CLI targets")
		if err := r.seedCLITargets(ctx, infra); err != nil {
			r.scanLogger.Error("seed", "CLI target seeding failed: "+err.Error())
			return fmt.Errorf("CLI target seeding failed: %w", err)
		}
		r.scanLogger.Info("seed", "seeding completed")
	case PhaseKnownIssueScan:
		r.setPhaseTag("known-issue-scan")
		r.scanLogger.Info("known-issue-scan", "phase started")
		if err := r.runKnownIssueScanPhase(ctx, infra); err != nil {
			zap.L().Error("KnownIssueScan phase failed", zap.Error(err))
			r.scanLogger.Error("known-issue-scan", "phase failed: "+err.Error())
			tracker.noteError(err)
		} else {
			r.scanLogger.Info("known-issue-scan", "phase completed")
			r.deduplicateFindings(ctx, "KnownIssueScan")
		}
	case PhaseDynamicAssessment:
		r.setPhaseTag("dynamic-assessment")
		activeModules, passiveModules := r.resolveAllModules(infra)
		if len(activeModules) > 0 || len(passiveModules) > 0 {
			r.scanLogger.InfoWithMeta("dynamic-assessment", "phase started", map[string]interface{}{
				"active_modules":  len(activeModules),
				"passive_modules": len(passiveModules),
			})
			if err := r.runDynamicAssessmentPhase(ctx, infra, activeModules, passiveModules); err != nil {
				zap.L().Error("Dynamic-assessment phase failed", zap.Error(err))
				r.scanLogger.Error("dynamic-assessment", "phase failed: "+err.Error())
				tracker.noteError(err)
			} else {
				r.scanLogger.Info("dynamic-assessment", "phase completed")
			}
		} else {
			zap.L().Info("No modules to execute")
			r.scanLogger.Info("dynamic-assessment", "skipped, no modules to execute")
			// Skipped, not completed: a scan that ran no modules at all must not
			// be reportable as a clean assessment. It is still a COMPLETE scan —
			// nothing was missed, there was nothing to do — which is why
			// no_modules is the one skip reason Completion treats as benign.
			tracker.markSkipped(database.ReasonNoModules)
		}
	}
	return nil
}
