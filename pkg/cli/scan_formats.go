package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// generateReportFromDB queries data from the database and generates a report at
// the specified output path using the given generator function. projectUUID
// scopes the query: "" exports the whole DB (stateless temp DB), a non-empty
// value scopes to one project so a persisted report matches the sibling jsonl
// export and never leaks other projects' findings. scanUUID further restricts the
// findings to a single scan (empty = all of the project's), so a persisted scan's
// report reflects that run rather than the project's whole history.
func generateReportFromDB(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID, scanUUID string, rf reportFormatEntry, onTrim func(output.ReportTrimInfo)) error {
	autoTarget, autoDuration := computeReportMeta(ctx, db)
	meta := output.HTMLReportMeta{
		Title:           "Vigolium Scan Report",
		Version:         getVersion(),
		ScanDuration:    autoDuration,
		ScanTarget:      autoTarget,
		ReportSharedURL: scanReportSharedURL,
		// nil keeps the generator's default inline "Note:" line; the stateless
		// export path passes a collector so the trim summary folds into "Exports".
		OnTrim: onTrim,
	}
	// Prefer the streaming generator when the format has one: it renders the
	// report by pulling rows one at a time instead of loading the whole result
	// set into memory. The HTML renderer derives the displayed request/response
	// bodies from the raw bytes (HTTPRecord.MarshalJSON) and only then drops the
	// redundant raw_request/raw_response copies, so those columns MUST be loaded;
	// honor only an explicit --omit-response, never force it on here.
	if rf.streamGenerate != nil {
		produce := func(emit func(any) error) error {
			// Reports render the whole envelope: --export-only documents itself as
			// narrowing the jsonl stream, and a report with its findings silently
			// removed is worse than no report.
			return streamExportData(ctx, db, fullExportScope, omitResponse, projectUUID, scanUUID, emit)
		}
		return rf.streamGenerate(produce, outputPath, meta)
	}
	// Materialized branch: MUST carry scanUUID too. The streaming branch above
	// already scoped to the current scan, but `report`, `pdf` and `sarif` have no
	// streaming generator, so they fell through here and rendered the project's
	// whole finding history as if it were this run's result — contradicting this
	// function's own contract and, for sarif, re-reporting every historical finding
	// to GitHub code scanning on each scan.
	items, err := queryExportData(ctx, db, omitResponse, projectUUID, scanUUID)
	if err != nil {
		return err
	}
	return rf.generate(items, outputPath, meta)
}

// parseFormats splits a comma-separated format string, defaulting to "console".
func parseFormats(raw string) []string {
	parts := strings.Split(raw, ",")
	formats := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			formats = append(formats, p)
		}
	}
	if len(formats) == 0 {
		return []string{"console"}
	}
	return formats
}

// scanOutputFormats is the canonical set of --format values the scan commands
// and the agentic-scan -S export accept — one list, because both materialize
// their output through the same exporter (finishStatelessExport).
var scanOutputFormats = []string{"console", "jsonl", "html", "report", "pdf", "sarif", "sqlite", "fs"}

// formatAliases maps every accepted alias spelling onto its canonical format
// name, so only canonical names reach the downstream switches and path helpers.
//
// One table for both `--format` flavors rather than one per command: `fs` is
// valid on the scan commands AND on `vigolium export`, so a per-command table
// would have to carry its aliases twice — the kind of split that leaves an
// alias working on one command and unknown on the other. An alias that
// canonicalizes to a format a given command does not accept still fails that
// command's own valid-list check, and the error quotes what the user typed.
var formatAliases = map[string]string{
	"md":          "markdown",
	"gz":          "bundle",
	"sqlite3":     "sqlite",
	"db":          "sqlite",
	"file-system": "fs",
}

// canonicalFormat resolves one --format token to its canonical name. Matching is
// case-insensitive, which `vigolium export` already was; the scan side used to
// fold case only for the sqlite aliases, so `--format SQLITE` worked while
// `--format HTML` did not.
func canonicalFormat(token string) string {
	lower := strings.ToLower(strings.TrimSpace(token))
	if canonical, ok := formatAliases[lower]; ok {
		return canonical
	}
	return lower
}

// normalizeScanFormats canonicalizes aliases in place and rejects anything
// outside scanOutputFormats. Shared by reconcileOutputFormats and
// planAgentStateless so a format accepted by `scan -S` is accepted by
// `agent autopilot -S` too.
func normalizeScanFormats(formats []string) error {
	for i, f := range formats {
		formats[i] = canonicalFormat(f)
		if !slices.Contains(scanOutputFormats, formats[i]) {
			return usageErrorf("invalid --format value %q; valid formats: %s", f, strings.Join(scanOutputFormats, ", "))
		}
	}
	return nil
}

// reconcileOutputFormats applies --json and --ci-output-format overrides to
// OutputFormats and validates the result. Shared by scan and scan-url commands.
func reconcileOutputFormats(opts *types.Options) error {
	if globalJSON && len(opts.OutputFormats) == 1 && opts.OutputFormats[0] == "console" {
		opts.OutputFormats = []string{"jsonl"}
	}
	if opts.HasFormat("jsonl") {
		opts.JSONOutput = true
	}
	if globalCIOutput {
		opts.CIOutput = true
		opts.OutputFormats = []string{"jsonl"}
		opts.JSONOutput = true
		opts.Silent = true
	}
	if err := normalizeScanFormats(opts.OutputFormats); err != nil {
		return err
	}
	// The sqlite format dumps this run's database to a standalone file, which is
	// only well-defined in stateless mode (a per-run temp DB). A persisted run
	// writes into the shared project DB, where "this scan's sqlite" is ambiguous.
	if opts.HasFormat("sqlite") && !globalStateless {
		return usageErrorf("--format sqlite requires -S/--stateless (it exports the standalone per-run database; for the persisted DB use `vigolium export`)")
	}
	// Route jsonl through the post-scan project-scoped envelope export so the
	// scan output matches `vigolium export`/stateless. CI output keeps its own
	// findings-only emitter (see outputScanResult), so leave it on the legacy
	// live path.
	opts.DeferredJSONLExport = opts.HasFormat("jsonl") && !opts.CIOutput
	return nil
}

// reportFormatEntry maps a --format value to its generator and display label.
type reportFormatEntry struct {
	format string
	label  string
	// generate materializes all items, then renders. Used when streamGenerate
	// is nil, and as the fallback path for the streaming generators.
	generate func([]any, string, output.HTMLReportMeta) error
	// streamGenerate, when set, renders the report by pulling items one at a
	// time from a producer, so the result set never lives in memory at once.
	streamGenerate func(output.ReportItemProducer, string, output.HTMLReportMeta) error
	beforeMsg      string // optional stderr message before generation
}

var reportFormats = []reportFormatEntry{
	{format: "html", label: "HTML report", generate: output.GenerateHTMLReport, streamGenerate: output.GenerateHTMLReportStreaming},
	{format: "report", label: "Document report", generate: output.GenerateDocumentReport},
	{format: "pdf", label: "PDF report", generate: output.GeneratePDFReport, beforeMsg: "Generating PDF report (headless Chrome)..."},
	{format: "sarif", label: "SARIF report", generate: output.GenerateSARIFReport},
}

// formatNeedsOutput reports whether a format writes a file the command cannot
// name on its own, so `--format X` without `-o` must be rejected rather than
// silently producing nothing. Shared by the scan commands and `export`/`import`,
// which previously carried two predicates whose defaults for an unrecognized
// format were opposite.
//
// A deny-list on purpose: `console` writes nothing, `jsonl` streams to stdout,
// and `fs` defaults its base to the cwd — every other format names a file.
// Stated the other way round, as a list of file formats, a newly added format
// defaults to "needs no -o" and silently no-ops, which is exactly how `sarif`
// shipped able to be requested and unable to be written.
func formatNeedsOutput(format string) bool {
	switch canonicalFormat(format) {
	case "console", "jsonl", "fs":
		return false
	}
	return true
}

// maybeGenerateReports generates all requested file-based reports post-scan and
// returns the joined per-format failures.
//
// Every format named on the command line is a requested output, and a scan that
// could not write one did not do what it was asked. It used to print "Failed to
// generate html" to stderr and exit 0, so a CI job that asked for a report and
// read the exit code was told the run succeeded while the file it was about to
// publish did not exist. The error now reaches the caller, which folds it in
// with recordExportFailure.
//
// Nothing is printed for a failure here, for the same reason as
// finishStatelessExport: the root handler renders the returned error once, and
// printing as well announced the same cause twice in two wordings. Each format
// is still attempted independently, so one unwritable destination does not cost
// the others.
func maybeGenerateReports(db *database.DB, opts *types.Options) error {
	if opts.Output == "" {
		return nil
	}
	ctx := context.Background()
	// Scope the report's findings to this scan on a persisted (shared) DB, so a
	// re-run's report reflects that run rather than the project's whole history. A
	// stateless run's temp DB already holds only this scan, so it needs no filter.
	scanScope := ""
	if !opts.Stateless {
		scanScope = opts.ScanUUID
	}
	var failures []error
	for _, rf := range reportFormats {
		if !opts.HasFormat(rf.format) {
			continue
		}
		outPath := opts.OutputPathForFormat(rf.format)
		if rf.beforeMsg != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
		}
		if err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, exportProjectScope(opts), scanScope, rf, nil); err != nil {
			failures = append(failures, fmt.Errorf("generate %s %s: %w", rf.label, outPath, err))
			continue
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", terminal.InfoSymbol(), rf.label, terminal.Cyan(outPath))
	}
	return errors.Join(failures...)
}
