package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// auditBundleReportName is the report filename used inside an --output-dir
// bundle. Distinct from defaultAuditStatelessReport (which nests under a
// vigolium-result/ subdir); inside a user-named bundle the report sits at the
// top level.
const auditBundleReportName = "vigolium-audit-report.html"

// auditBundleRawSubdir is the folder name each driver's raw scanner output is
// copied into within the --output-dir bundle. Matches the harness SessionSubdir.
const auditBundleRawSubdir = "vigolium-results"

// resolveAuditReportDest computes the HTML report destination for a --stateless
// run and, when --output-dir is set, the resolved bundle directory that also
// receives the raw vigolium-results copy.
//
// {ts}/{project-uuid} placeholders in outputDir are expanded once here so the
// report and the raw copy share the same resolved directory. The returned
// bundleDir is empty when --output-dir was not set — callers then fall back to
// -o (or the emit default) for the report and skip the raw copy.
//
// With a bundle dir: an empty -o defaults to <bundle>/vigolium-audit-report.html;
// an absolute path or gs:// URL wins verbatim (escapes the bundle); a relative
// -o is nested under the bundle.
func resolveAuditReportDest(outputDir, oFlag string) (reportDest, bundleDir string, err error) {
	outputDir = strings.TrimSpace(outputDir)
	oFlag = strings.TrimSpace(oFlag)
	if outputDir == "" {
		// No bundle: -o (empty falls through to the emit default) wins.
		return oFlag, "", nil
	}
	resolvedDir, err := expandOutputPlaceholders(outputDir)
	if err != nil {
		return "", "", err
	}
	switch {
	case oFlag == "":
		reportDest = filepath.Join(resolvedDir, auditBundleReportName)
	case storage.IsGCSURI(oFlag) || filepath.IsAbs(oFlag):
		reportDest = oFlag // explicit destination wins verbatim
	default:
		reportDest = filepath.Join(resolvedDir, oFlag)
	}
	return reportDest, resolvedDir, nil
}

// emitAuditStatelessArtifacts renders the --stateless HTML report and, when
// --output-dir is set, bundles a copy of the raw vigolium-results/ tree(s)
// alongside it. Best-effort: every failure warns to stderr rather than aborting
// the run — the report/bundle is a convenience, the findings already imported.
func emitAuditStatelessArtifacts(ctx context.Context, db *database.DB, projectUUID, absTarget string, startedAt time.Time, plans []*driverPlan, allFailed bool) {
	switch {
	case allFailed:
		fmt.Fprintf(os.Stderr, "%s --stateless: skipping HTML report — no audit driver completed\n",
			terminal.WarningSymbol())
		return
	case db == nil:
		fmt.Fprintf(os.Stderr, "%s --stateless: skipping HTML report — database unavailable\n",
			terminal.WarningSymbol())
		return
	}

	reportDest, bundleDir, err := resolveAuditReportDest(auditOutputDir, auditReportOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s --output-dir: %v\n", terminal.WarningSymbol(), err)
		return
	}

	if err := emitAuditStatelessReport(ctx, db, projectUUID, reportDest, absTarget, startedAt); err != nil {
		fmt.Fprintf(os.Stderr, "%s --stateless: HTML report generation failed: %v\n",
			terminal.WarningSymbol(), err)
	}

	// --output-dir also collects a copy of the raw scanner output into the
	// bundle (the source-tree copy is left in place per --keep-raw).
	if bundleDir == "" {
		return
	}
	if n, err := bundleAuditRawResults(bundleDir, plans); err != nil {
		fmt.Fprintf(os.Stderr, "%s --output-dir: raw results copy failed: %v\n",
			terminal.WarningSymbol(), err)
	} else if n > 0 && !globalJSON {
		fmt.Printf("%s Bundled raw results → %s\n",
			terminal.SuccessSymbol(), terminal.Cyan(bundleDir))
	}
}

// bundleAuditRawResults copies each ran driver's synced vigolium-results/ tree
// into the --output-dir bundle and returns how many were copied. The source is
// the always-retained session copy at <plan.sessionDir>/vigolium-results
// (independent of --keep-raw/--clean-raw, which only govern the source-tree
// copy). With one driver the tree lands at <bundleDir>/vigolium-results; with
// several, each is namespaced under <bundleDir>/<driver>/vigolium-results so
// they don't collide. Drivers that failed or produced no output are skipped.
func bundleAuditRawResults(bundleDir string, plans []*driverPlan) (int, error) {
	// Keep only drivers that actually produced a raw-output folder. The count
	// gates namespacing below, so it must be known before the first copy.
	ran := make([]*driverPlan, 0, len(plans))
	for _, p := range plans {
		if p == nil || p.runErr != nil {
			continue
		}
		src := filepath.Join(p.sessionDir, auditBundleRawSubdir)
		if info, statErr := os.Stat(src); statErr != nil || !info.IsDir() {
			continue
		}
		ran = append(ran, p)
	}

	copied := 0
	for _, p := range ran {
		src := filepath.Join(p.sessionDir, auditBundleRawSubdir)
		dest := filepath.Join(bundleDir, auditBundleRawSubdir)
		if len(ran) > 1 {
			dest = filepath.Join(bundleDir, p.name, auditBundleRawSubdir)
		}
		// CopyDirContents streams each file and creates dest (and bundleDir as
		// its ancestor); nothing is written when ran is empty.
		if err := dbimport.CopyDirContents(src, dest); err != nil {
			return copied, fmt.Errorf("copy %s results: %w", p.name, err)
		}
		copied++
	}
	return copied, nil
}

// defaultAuditStatelessReport is the report destination used by `vigolium
// (agent) audit -S` when no -o/--output override is given. Relative to the
// current working directory; the parent dir is created if missing.
const defaultAuditStatelessReport = "vigolium-result/vigolium-audit-report.html"

// emitAuditStatelessReport renders the self-contained HTML report for a
// --stateless audit run. The audit drivers already imported the on-disk
// vigolium-results folder(s) into the throwaway temp DB, so this queries that
// DB (scoped to the run's project) and feeds the findings through the exact
// generator behind `vigolium import --format html` (reportGenerator), keeping
// the output identical to the manual two-step import.
//
// outputArg overrides the destination (-o/--output); empty falls back to
// defaultAuditStatelessReport. The path supports gs:// upload and {ts}
// placeholders via resolveExportOutput, mirroring `vigolium export`.
func emitAuditStatelessReport(ctx context.Context, db *database.DB, projectUUID, outputArg, target string, startedAt time.Time) error {
	outputArg = strings.TrimSpace(outputArg)
	if outputArg == "" {
		outputArg = defaultAuditStatelessReport
	}

	rf, ok := reportGenerator("html")
	if !ok {
		return fmt.Errorf("html report generator unavailable")
	}
	gen, defaultTitle := rf.Render, rf.DefaultTitle

	localOutput, finalize, err := resolveExportOutput(ctx, outputArg)
	if err != nil {
		return err
	}
	// Ensure the parent directory exists for a local destination (e.g. the
	// default vigolium-result/). resolveExportOutput returns a temp path for
	// gs:// URLs, which already exists, so only create dirs for real paths.
	if !storage.IsGCSURI(outputArg) {
		if dir := filepath.Dir(localOutput); dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return fmt.Errorf("create report directory %s: %w", dir, mkErr)
			}
		}
	}

	// The throwaway temp DB holds only this run's data, so a project-scoped
	// query returns exactly the audit's findings.
	var findings []*database.Finding
	q := scopeProjectBun(db.NewSelect().Model(&findings).
		Where("record_kind IS NULL OR record_kind = '' OR record_kind = ?", database.RecordKindFinding).
		OrderExpr("found_at DESC"), projectUUID)
	if err := q.Scan(ctx); err != nil {
		return fmt.Errorf("query findings for report: %w", err)
	}

	items := make([]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, exportEnvelope{Type: "finding", Data: f})
	}

	meta := output.HTMLReportMeta{
		Title:   defaultTitle,
		Version: getVersion(),
	}
	if target != "" {
		meta.ScanTarget = terminal.ShortenHome(target)
	}
	if d := time.Since(startedAt).Round(time.Second); d > 0 {
		meta.ScanDuration = d.String()
	}

	if !globalJSON {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
			terminal.BoldCyan(fmt.Sprintf("Generating HTML report — %d findings ...", len(findings))))
	}
	if err := gen(items, localOutput, meta); err != nil {
		return err
	}
	if err := finalize(); err != nil {
		return err
	}

	fmt.Printf("%s Report written: %s (%d findings)\n",
		terminal.SuccessSymbol(), terminal.Cyan(outputArg), len(findings))
	return nil
}
