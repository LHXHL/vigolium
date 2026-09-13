package cli

import (
	"context"
	"io"
	"os"
	"sort"

	"github.com/vigolium/vigolium/pkg/database"
)

const (
	agentSummaryTopFindings = 20  // cap on top_findings rendered in the summary
	agentSummaryScanCap     = 500 // cap on rows fetched to rank top_findings
)

// agentStreamSink returns the writer for an agent run's live output: stderr
// under --json (stdout is reserved for the final JSON summary), otherwise
// stdout. Shared by autopilot / swarm / audit so the routing rule lives once.
func agentStreamSink() io.Writer {
	if globalJSON {
		return os.Stderr
	}
	return os.Stdout
}

// resolveAgenticScanTree returns the root agentic-scan UUID plus any direct
// child runs (audit driver legs, swarm sub-runs link via parent_run_uuid), so a
// single root UUID resolves every finding the run produced regardless of which
// leaf scan recorded it.
func resolveAgenticScanTree(ctx context.Context, db *database.DB, root string) []string {
	uuids := []string{root}
	if db == nil || root == "" {
		return uuids
	}
	var children []string
	_ = db.NewSelect().Model((*database.AgenticScan)(nil)).
		Column("uuid").
		Where("parent_run_uuid = ?", root).
		Scan(ctx, &children)
	return append(uuids, children...)
}

// emitAgentScanJSONSummary prints a compact, machine-readable summary of an
// agentic scan (autopilot / swarm / audit) to stdout when --json is set. It
// gives a coding agent a usable handle on the run — the scan UUID, finding
// counts by severity, the session dir, the most severe findings, and a ready
// follow-up query — instead of forcing it to chase files under the session dir.
// A no-op unless --json is set, so default console output is unchanged.
func emitAgentScanJSONSummary(repo *database.Repository, projectUUID, agenticScanUUID, status, sessionDir string) {
	if !globalJSON || repo == nil || agenticScanUUID == "" {
		return
	}
	ctx := context.Background()
	db := repo.DB()
	uuids := resolveAgenticScanTree(ctx, db, agenticScanUUID)

	// Accurate counts by severity across the whole scan tree.
	counts, _ := database.CountFindingsByAgenticScans(ctx, db, uuids)
	var total int64
	for _, c := range counts {
		total += c
	}

	// Top findings: bounded fetch, ranked by severity desc.
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		ProjectUUID:      projectUUID,
		AgenticScanUUIDs: uuids,
		Limit:            agentSummaryScanCap,
		SortBy:           "found_at",
	}).Execute(ctx)
	if err != nil {
		findings = nil
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	if len(findings) > agentSummaryTopFindings {
		findings = findings[:agentSummaryTopFindings]
	}
	top := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		top = append(top, compactFindingView(f, nil, agentViewOptions{}))
	}

	_ = writeAgentJSON(map[string]any{
		"agentic_scan_uuid":  agenticScanUUID,
		"project_uuid":       projectUUID,
		"status":             status,
		"session_dir":        sessionDir,
		"total_findings":     total,
		"counts_by_severity": counts,
		"top_findings":       top,
		"query":              followUpQuery("finding", "--agentic-scan", agenticScanUUID, "--json", "--with-records"),
	})
}
