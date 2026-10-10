package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/memlimit"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// executeNativeScan runs one full native scan pass against the current
// scanOpts. In stateless mode it allocates a fresh temporary SQLite database
// and tears it down on return so callers can invoke it once per target.
func executeNativeScan(cmd *cobra.Command, settings *config.Settings, strategyName string) (err error) {
	// Wall-clock anchor for the whole scan pass, surfaced in the completion
	// summary. Captured before DB setup so it reflects total time, not just the
	// scanning legs.
	scanStart := time.Now()

	// Stateless mode: create a temporary SQLite database for this run only.
	var statelessDBPath string
	if scanOpts.Stateless {
		tmpFile, tmpErr := scratch.CreateTemp("stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		// Registered first, so it runs LAST (defers are LIFO) — after db.Close
		// and after the db-isolate merge. Removing or preserving a database that
		// still has an open handle would be the wrong order in both directions.
		defer func() { err = releaseStatelessDB(statelessDBPath, err) }()

		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
	}

	// One signal handler for the whole invocation, installed before any of the
	// setup below. The old one went in immediately before RunNativeScan, so a
	// Ctrl+C during a schema migration, a session login or target expansion was
	// not trapped by the scan at all.
	signals := startScanSignals(scanStart)
	defer signals.stop()

	// The terminal event is emitted HERE, before --db-isolate registers its
	// merge, so LIFO runs it after that merge has either landed or failed: the
	// stream's last word on the scan must include whether the results reached
	// the database the operator named. emitTerminalEvent is assigned later (the
	// emitter needs the open database and the pinned uuid), so the holder is
	// nil-checked rather than pre-filled.
	var emitTerminalEvent func(error)
	defer func() {
		if emitTerminalEvent != nil {
			emitTerminalEvent(err)
		}
	}()

	// DB-isolate mode: scan into a private temporary SQLite database, then merge
	// the results into the real --db (or default DB) once the scan finishes, so
	// many parallel scan processes can share one --db without contending on a
	// single SQLite writer. Registered before the DB opens so the merge runs
	// after db.Close() (defers are LIFO), once the scratch's writes are flushed.
	finish, dErr := dbIsolateBegin(settings, scanOpts.Silent)
	if dErr != nil {
		return dErr
	}
	defer func() { err = finish(err) }()

	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancelSetup := setupContext(settings)
	defer cancelSetup()
	if err := db.EnsureSchemaReady(ctx); err != nil {
		return wrapSetupError(ctx, db.Driver(), "database schema setup", err)
	}

	repo := database.NewRepository(db)
	zap.L().Debug("Database initialized successfully",
		zap.String("driver", db.Driver()))

	// Stateless + -o + default console format: capture the full verbose
	// console session (banner, scan summary, phase progress, result lines)
	// into the output file as a faithful transcript, instead of the minimal
	// per-record DB export. Started before printScanSummary so the banner is
	// included. Other --format values keep the post-scan DB export below.
	transcriptActive := scanOpts.Stateless && scanOpts.Output != "" &&
		!scanOpts.Silent && !globalJSON && !globalCIOutput &&
		len(scanOpts.OutputFormats) == 1 && scanOpts.OutputFormats[0] == "console"
	if transcriptActive {
		transcriptPath := scanOpts.Output
		tc, tErr := startTranscriptCapture(transcriptPath)
		if tErr != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to start transcript capture (%v); falling back to record export\n",
				terminal.WarnPrefix(), tErr)
			transcriptActive = false
		} else {
			defer func() {
				tc.Stop()
				fmt.Fprintf(os.Stderr, "%s Transcript written to %s\n",
					terminal.InfoSymbol(), terminal.Cyan(transcriptPath))
			}()
		}
	}

	// Pin the scan UUID before the banner so the config summary can show it and
	// the runner reuses the same identifier instead of minting its own.
	scanOpts.ScanUUID = pinnedOrNewUUID(scanOpts.ScanUUID)

	// Scope admission over the targets this run is about to seed, for the
	// banner and scan.started (the runner recomputes it and owns the verdict).
	// Assigned on every pass: executeNativeScan runs once per target under the
	// per-host fan-outs, and a stale verdict must not leak into the next one.
	scanOpts.TargetAdmission = scanTargetAdmission(settings, scanOpts, cmd != nil && cmd.Flags().Changed("input-mode"))

	// Machine event stream (--events). Installed here, after the uuid is pinned
	// and the database is open, so scan.started can name both. The totals are
	// gathered as the OUTERMOST of the post-scan defers below — while the
	// database is still open — and the line itself is written by the holder
	// registered above, after the db-isolate merge.
	prepareTerminalEvent, emitEvents, evErr := beginScanEventStream(db, scanOpts, settings, strategyName, scanStart)
	if evErr != nil {
		return evErr
	}
	emitTerminalEvent = emitEvents
	defer func() { prepareTerminalEvent(err) }()
	// Print scan summary banner (after DB init so we can show HTTP record count)
	printScanSummary(scanOpts, settings, strategyName, repo, "")
	scanOpts.ScanConfigPrinted = true

	// For stateless mode with --output: suppress StandardWriter's live file
	// output and export the full database post-scan. This covers console
	// (default), jsonl, and report formats so -o always produces a populated
	// file even when the phase only ingests HTTP records (e.g. discovery) and
	// emits no findings for StandardWriter to write.
	var statelessOutputPath string
	if scanOpts.Stateless && scanOpts.Output != "" {
		statelessOutputPath = scanOpts.Output
		savedOutput := scanOpts.Output
		scanOpts.Output = "" // prevent StandardWriter from creating the output file
		defer func() { scanOpts.Output = savedOutput }()
	}
	// Defer stateless export so all exit paths are covered automatically. When
	// a transcript is being captured, skip the console export so it does not
	// truncate and clobber the transcript file at the same path.
	defer func() {
		recordExportFailure(&err, finishStatelessExport(db, scanOpts, statelessOutputPath, transcriptActive))
	}()
	// Persisted (non-stateless) --format jsonl emits the same scan-scoped
	// unified envelope post-scan instead of StandardWriter's live nuclei stream
	// (suppressed via DeferredJSONLExport). No-ops for stateless and CI runs.
	defer func() {
		if skipDeferredJSONLExport(err, scanOpts.Stateless, statelessOutputPath) {
			return
		}
		recordExportFailure(&err, finishScanJSONLExport(db, scanOpts))
	}()

	// If -i was explicitly provided, use two-phase ingest-then-scan
	hasInputFile := globalInput != "" && globalInput != "-"
	if hasInputFile {
		return runScanWithIngest(settings, db, repo, scanStart)
	}

	// If no targets/input/stdin, scan the DB records. runScanCmd has already
	// required --all-records for this (or warned on a TTY), see
	// resolveScanTargetSource.
	hasTargets := len(scanOpts.Targets) > 0
	hasTargetFile := len(scanOpts.TargetsFilePaths) > 0
	hasStdin := scanOpts.Stdin
	if !hasTargets && !hasTargetFile && !hasStdin {
		return runDBScanFn(settings, db, repo, scanStart)
	}

	// Promote -T/--target-file lines into scanOpts.Targets so the phases that
	// seed from the CLI target list (spidering's crawl seeds, deparos content
	// discovery) actually receive them. Runs after the fan-out dispatch in
	// runNativeScan and after printScanSummary, both of which read
	// TargetsFilePaths, and before the stdin block so a -T list survives the
	// raw-stdin SliceSource branch too.
	if err := seedTargetsFromTargetFiles(scanOpts); err != nil {
		return err
	}

	// Smart stdin detection: peek at piped content to detect raw HTTP or curl
	// format. Skipped when -I names a specific non-list format — that is an
	// explicit instruction the detector must not overrule — but an explicit
	// -I urls still comes through here, because the point of this block is to
	// land a piped URL list in scanOpts.Targets rather than in a StdinSource
	// the target-seeded phases never see. (An unset -I defaults to "urls", so
	// the target-list test alone admits the auto-detect case too.)
	inputModeExplicit := cmd.Flags().Changed("input-mode")
	if hasStdin && source.IsTargetListFormat(scanOpts.InputFileMode) {
		// Usually already drained by prefetchScanStdin in runScanCmd.
		raw, readErr := takeScanStdin()
		if readErr != nil {
			return fmt.Errorf("failed to read stdin: %w", readErr)
		}
		content := strings.TrimSpace(string(raw))
		// An explicit -I urls pins the format; only an unset -I is auto-detected.
		if stdinHoldsRawRequests(content, inputModeExplicit) {
			detected := detect.DetectStdinFormat(content)
			// Raw HTTP or curl — parse eagerly and use SliceSource
			items, parseErr := detect.ParseStdinContent(content, detected)
			if parseErr != nil {
				return fmt.Errorf("failed to parse stdin as %s: %w", detected, parseErr)
			}
			inputSrc := source.NewSliceSource(items, scanOpts.Modules)
			scanOpts.Stdin = false

			scanRunner, runnerErr := runner.NewWithInputSource(scanOpts, inputSrc)
			if runnerErr != nil {
				return fmt.Errorf("failed to create scan runner: %w", runnerErr)
			}

			scanRunner.SetSettings(settings)
			if repo != nil {
				scanRunner.SetRepository(repo)
			}

			// Close before reporting (so any flush lands in the DB the reports
			// read) — matching the main runner.New path below.
			scanErr := runNativeScanPass(scanRunner)
			if scanErr != nil {
				return scanErr
			}
			recordExportFailure(&err, reportNativeScanSuccess(db, settings, repo, scanStart))
			return err
		}
		// URLs — fall through to the runner.New() path below. Stdin is already
		// drained, so the lines are passed as targets rather than left to a
		// StdinSource (which would also leave the target-seeded phases empty).
		seedTargetsFromStdinLines(scanOpts, content)
		scanOpts.Stdin = false
	}

	// Returned, not zap.L().Fatal: Fatal calls os.Exit(1), which runs none of the
	// defers above — the event stream never writes its scan.finished, the
	// stateless export never materializes, the database is never closed, and the
	// -j error envelope is never emitted. A consumer saw a truncated stream and
	// exit 1 with no stated cause.
	scanRunner, err := runner.New(scanOpts)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	if scanRunner == nil {
		return nil
	}

	// Set settings and repository on runner
	scanRunner.SetSettings(settings)
	if repo != nil {
		scanRunner.SetRepository(repo)
	}

	scanErr := runNativeScanPass(scanRunner)
	// A failed scan must abort visibly: returning the error makes cobra print it
	// (it's an ErrorLevel-and-above world by default, so the old INFO log was
	// invisible without --verbose) and exit non-zero, and skips the "completed"
	// banner below — which would otherwise claim success over stale/partial DB
	// data (e.g. a session-init failure where no scanning ran at all).
	if scanErr != nil {
		return scanErr
	}

	recordExportFailure(&err, reportNativeScanSuccess(db, settings, repo, scanStart))
	return err
}

// reportNativeScanSuccess runs the post-scan tail shared by every native-scan
// entry point: report-file generation, result upload, and the completion
// summary banner. It is invoked only when RunNativeScan returned no error — a
// failed scan returns its error to the caller instead, so this success banner
// never paints over a scan that didn't actually run. A scan curtailed by
// --scanning-max-duration returns nil (graceful), so time-boxed partial scans
// still reach this path and keep their reports.
//
// It returns the joined failures of the three artifact-producing steps. The
// summary, the finding/traffic prints and the gate still run after one of them
// fails, deliberately: the scan's results exist and are worth showing, and the
// gate's verdict is about the findings rather than about the files. What changes
// is that the caller folds the error in with recordExportFailure, so a run that
// did not write what it was asked for exits non-zero instead of printing
// "Failed to generate html" and exiting 0.
func reportNativeScanSuccess(db *database.DB, settings *config.Settings, repo *database.Repository, scanStart time.Time) error {
	// The upload is the one step that is NOT shared with the lightweight
	// commands: it is opt-in on --upload-results, but it also fires the
	// configured webhook unconditionally, and scan-url/scan-request have never
	// done that. Keeping it here rather than in reportScanCompletion is what lets
	// both callers share the rest without changing what either one emits.
	return errors.Join(
		reportScanCompletion(db, settings, repo, scanOpts, scanStart),
		uploadNativeScanResults(settings, scanOpts, repo),
	)
}

// reportScanCompletion is the artifact-and-report tail every native-scan entry
// point runs, lightweight commands included: reports, the fs tree, the
// completion summary, the optional finding/traffic prints, and the --fail-on
// gate. opts is a parameter rather than the scanOpts global precisely so
// runRunnerScan can call it — it was a hand-copy of this body for want of one
// argument.
func reportScanCompletion(
	db *database.DB,
	settings *config.Settings,
	repo *database.Repository,
	opts *types.Options,
	scanStart time.Time,
) error {
	// maybeGenerateReports self-guards on opts.Output=="" (blanked on the
	// stateless path, where finishStatelessExport handles reports instead).
	artifacts := errors.Join(
		maybeGenerateReports(db, opts),
		finishFSExport(db, opts),
	)
	if !opts.Silent {
		hosts := summaryScopeHosts(context.Background(), repo, settings, opts.Targets, opts.ProjectUUID, opts.ScanUUID)
		printScanCompletionSummary(repo, opts.ProjectUUID, opts.ScanUUID, hosts, time.Since(scanStart))
	}
	maybePrintScanFindings(context.Background(), db, opts.ProjectUUID, opts.ScanUUID)
	maybePrintScanTraffic(context.Background(), db, opts.ProjectUUID)
	evaluateFailOnGate(repo, opts.ProjectUUID, opts.ScanUUID, opts.Silent)
	return artifacts
}

// skipDeferredJSONLExport reports whether the deferred persisted-jsonl export
// must not run.
//
// One predicate, because every native-scan entry point registers that defer and
// the rule is subtle enough that a second copy drifts:
//
//   - stateless WITH -o: finishStatelessExport already materializes every format
//     to the file, and opts.Output is temporarily blanked, so
//     finishScanJSONLExport cannot detect this case itself — without this guard
//     it would ALSO stream the envelope to stdout (double output).
//   - a hard-failed persisted scan: don't write a success-looking file or stream
//     of stale or partial project data (mirrors the skipped "completed" banner).
//     Stateless is exempt — its temp DB is discarded after the run, so the stdout
//     stream is the only chance to surface whatever was found.
//   - an export failure is NOT a failed scan: an unwritable html path says
//     nothing about the findings, and skipping the jsonl export over it loses the
//     one format that would still have landed. Each --format is attempted
//     independently (see isExportFailure).
func skipDeferredJSONLExport(err error, stateless bool, statelessOutputPath string) bool {
	if stateless && statelessOutputPath != "" {
		return true
	}
	return err != nil && !stateless && !isExportFailure(err)
}

// runScanWithIngest delegates to the Runner's 3-phase pipeline when -i is provided.
// The Runner's Phase 1 ingests the input file, Phase 2 runs KnownIssueScan if enabled,
// and Phase 3 scans from DB with all modules.
func runScanWithIngest(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Auto-detect format from file extension
	inputFormat := globalInputMode
	if inputFormat == "urls" {
		if detected := detectInputFormat(globalInput); detected != "" {
			inputFormat = detected
			zap.L().Info("Auto-detected input format", zap.String("format", inputFormat))
		}
	}

	// OpenAPI defaults: auto-enable UseSpecServers when no -t given
	useSpecServers := globalSpecURL
	if (inputFormat == "openapi" || inputFormat == "swagger") &&
		len(globalTargets) == 0 && !useSpecServers {
		useSpecServers = true
		zap.L().Info("Auto-enabled --spec-url (no -t provided)")
	}

	// Create InputSource from the input file
	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:       globalTargets,
		FilePath:      globalInput,
		Format:        inputFormat,
		BufferSize:    100,
		EnableModules: scanOpts.Modules,
	})
	if err != nil {
		return fmt.Errorf("failed to create input source: %w", err)
	}

	// Configure spec-format options on the file parser. FirstFileSource unwraps a
	// MultiSource so the override still lands when -t is combined with -i (a bare
	// *FileSource assertion would miss it). The -t target is the OpenAPI BaseURL /
	// WSDL endpoint host override; the shared --spec-header / --spec-var flags
	// carry headers and field values.
	if fs := source.FirstFileSource(inputSource); fs != nil {
		var targetURL string
		if len(globalTargets) > 0 {
			targetURL = globalTargets[0]
		}
		switch parser := fs.Format().(type) {
		case *openapi.Format:
			parser.SetOpenAPIOptions(openapi.Options{
				BaseURL:              targetURL,
				UseSpecServers:       useSpecServers,
				Headers:              ingestParseHeaders(globalSpecHeader),
				Variables:            ingestParseVariables(globalSpecVar),
				DefaultFallbackValue: globalSpecDefault,
			})
		case *wsdl.Format:
			parser.SetWSDLOptions(wsdl.Options{
				EndpointURL: targetURL,
				Headers:     ingestParseHeaders(globalSpecHeader),
				Variables:   ingestParseVariables(globalSpecVar),
			})
		}
	}

	// Create Runner with the input source — RunNativeScan handles all 3 phases
	scanRunner, err := runner.NewWithInputSource(scanOpts, inputSource)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess.
	//
	// runNativeScanPass owns the release, replacing a `defer Close()`: on the
	// interrupted-before-start path the runner is Discarded, and a deferred
	// Close would then block for the whole shutdown timeout waiting on a run
	// that never happened.
	if err := runNativeScanPass(scanRunner); err != nil {
		return err
	}

	var tailErr error
	recordExportFailure(&tailErr, reportNativeScanSuccess(db, settings, repo, scanStart))
	return tailErr
}

// runDBScan scans records already in the database (no explicit targets).
// Delegates to RunNativeScan(): Phase 1 is a no-op (empty source),
// Phase 2 runs KnownIssueScan if enabled, Phase 3 reads existing DB records.
func runDBScan(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Create Runner with an empty input source — Phase 1 becomes a no-op
	scanRunner, err := runner.NewWithInputSource(scanOpts, &emptySource{})
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess and runNativeScanPass.
	if err := runNativeScanPass(scanRunner); err != nil {
		return err
	}

	var tailErr error
	recordExportFailure(&tailErr, reportNativeScanSuccess(db, settings, repo, scanStart))
	return tailErr
}

// emptySource is an InputSource that immediately returns io.EOF.
// Used when no external input is provided (DB-only scan mode).
type emptySource struct{}

func (e *emptySource) Next(_ context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (e *emptySource) Close() error                                   { return nil }

// scanShutdownSignals are the signals that cancel a running scan.
//
// SIGTERM is here for parity with scanevents.TrapSignals, which has always
// trapped both. Trapping only SIGINT meant a SIGTERM (a `timeout`, a container
// stop, a supervisor) emitted a terminal scan.finished{interrupted} on the event
// stream — latching the emitter shut — while the runner carried on to completion
// and later wrote `completed | complete` to the scan row. The stream and the row
// disagreed, and the row's real terminal event was dropped by the once-latch. Now
// both paths take the same cancellation route — see scanSignalCoordinator, which
// is the single handler both facts now come from.
var scanShutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// heapCeilingConfigLine renders the memory-ceiling detail shown inside the
// Native Scan Configuration block under a parallel fan-out (-P > 1): plain
// (uncolored) descriptive text with only the byte amounts highlighted, matching
// the rest of the config lines. The common auto-derived case reads "Memory
// ceiling 12 GiB/process (auto from 36 GiB RAM)"; explicit/percent/disabled/
// inherited ceilings fall back to the raw note (which carries its own
// descriptor). Returns "" when there is nothing to report (machine too small or
// RAM undetectable).
func heapCeilingConfigLine(res memlimit.Result) string {
	if res.Note == "" {
		return ""
	}
	if res.Auto && res.TotalRAMBytes > 0 {
		return fmt.Sprintf("Memory ceiling %s/process (auto from %s RAM)",
			terminal.Orange(humanize.IBytes(uint64(res.LimitBytes))),
			terminal.Orange(humanize.IBytes(res.TotalRAMBytes)))
	}
	return res.Note
}
