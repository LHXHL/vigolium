package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

// Prior-context modes for --prior-context. auto (the default) renders the
// bounded table when there is prior data; summary is a one-line pointer; off
// disables it. "full" is accepted as a synonym for auto.
const (
	priorCtxAuto    = "auto"
	priorCtxSummary = "summary"
	priorCtxOff     = "off"
)

// Caps that keep the brief bounded regardless of how much traffic/how many
// findings the project holds — everything past the cap collapses to a
// "N more — use the tool" pointer, so the token cost is roughly fixed.
const (
	priorContextEndpointCap = 20
	priorContextFindingCap  = 10
)

// validatePriorContextMode normalizes and validates the --prior-context value.
func validatePriorContextMode(mode string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case "", priorCtxAuto, "full": // "full" is a back-compat synonym for auto
		return priorCtxAuto, nil
	case priorCtxSummary, priorCtxOff:
		return m, nil
	default:
		return "", usageErrorf("invalid --prior-context %q: want auto, summary, or off", mode)
	}
}

// buildPriorContextBrief renders a bounded summary of the traffic and findings
// ALREADY in the project DB (Burp imports, prior scans, prior findings) so the
// operator mines them instead of re-deriving from scratch. It is built before
// this run's pre-scan, so it reflects genuinely prior data.
//
// The brief is bounded no matter the DB size: totals + up to
// priorContextEndpointCap endpoints (deduped by method+path) + up to
// priorContextFindingCap findings, each with a "N more — use the tool" pointer.
// It also returns the record and finding counts (for the caller's log). brief is
// "" when the mode is off, there is no prior data, or the repo is nil.
func buildPriorContextBrief(ctx context.Context, repo *database.Repository, projectUUID, mode string) (brief string, records, findings int) {
	if repo == nil || mode == priorCtxOff {
		return "", 0, 0
	}

	recCount, hostCount := priorRecordTotals(ctx, repo, projectUUID)
	sevCounts, _ := database.CountFindingsBySeverity(ctx, repo.DB(), projectUUID)
	var findingTotal int64
	for _, n := range sevCounts {
		findingTotal += n
	}
	if recCount == 0 && findingTotal == 0 {
		return "", 0, 0 // nothing prior — every mode renders nothing
	}

	header := fmt.Sprintf("Traffic: %d records · %d hosts · Findings: %d%s",
		recCount, hostCount, findingTotal, formatSeverityCounts(sevCounts))
	if sources := priorSourceBreakdown(ctx, repo, projectUUID); sources != "" {
		header += "\nSources: " + sources
	}

	var b strings.Builder
	b.WriteString("## Prior context (already in the project DB — mine this before re-scanning)\n\n")
	b.WriteString(header)

	// summary mode: header + a one-line pointer, no table.
	if mode == priorCtxSummary {
		b.WriteString("\n\nQuery it first with `query_records` / `list findings` before re-deriving what's known.")
		return b.String(), recCount, int(findingTotal)
	}

	// auto: add the capped endpoint table + findings list.
	if table := priorEndpointTable(ctx, repo, projectUUID); table != "" {
		b.WriteString("\n\n")
		b.WriteString(table)
	}
	if list := priorFindingList(ctx, repo, projectUUID); list != "" {
		b.WriteString("\n\n")
		b.WriteString(list)
	}
	b.WriteString("\n\nQuery this traffic first (`query_records --source burp`, `list findings`) before re-deriving what's known.")
	return b.String(), recCount, int(findingTotal)
}

// priorRecordTotals returns the project's total http_record count and distinct
// hostname count. Errors degrade to zeros (the caller treats that as "no data").
func priorRecordTotals(ctx context.Context, repo *database.Repository, projectUUID string) (records, hosts int) {
	var row struct {
		Records int `bun:"records"`
		Hosts   int `bun:"hosts"`
	}
	err := repo.DB().NewSelect().
		Table("http_records").
		ColumnExpr("COUNT(*) AS records").
		ColumnExpr("COUNT(DISTINCT hostname) AS hosts").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &row)
	if err != nil {
		return 0, 0
	}
	return row.Records, row.Hosts
}

// priorSourceBreakdown returns a short "burp (1190), scanner (94)" string of the
// top record sources, so the operator knows how much came from Burp vs scans.
func priorSourceBreakdown(ctx context.Context, repo *database.Repository, projectUUID string) string {
	var rows []struct {
		Source string `bun:"source"`
		N      int    `bun:"n"`
	}
	err := repo.DB().NewSelect().
		Table("http_records").
		ColumnExpr("COALESCE(NULLIF(source, ''), 'scanner') AS source").
		ColumnExpr("COUNT(*) AS n").
		Where("project_uuid = ?", projectUUID).
		GroupExpr("1").
		OrderExpr("n DESC").
		Limit(5).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%s (%d)", r.Source, r.N))
	}
	return strings.Join(parts, ", ")
}

// priorEndpointTable renders up to priorContextEndpointCap endpoints (deduped by
// method+path, most-hit first) as a compact list, with a pointer to the rest.
func priorEndpointTable(ctx context.Context, repo *database.Repository, projectUUID string) string {
	var rows []struct {
		Method string `bun:"method"`
		Path   string `bun:"path"`
		Status int    `bun:"status"`
		N      int    `bun:"n"`
	}
	err := repo.DB().NewSelect().
		Table("http_records").
		ColumnExpr("method").
		ColumnExpr("path").
		ColumnExpr("MAX(status_code) AS status").
		ColumnExpr("COUNT(*) AS n").
		Where("project_uuid = ?", projectUUID).
		GroupExpr("method, path").
		OrderExpr("n DESC").
		Limit(priorContextEndpointCap).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return ""
	}

	// The fetched rows ARE the complete distinct set unless we hit the cap; only
	// then pay for the full DISTINCT scan to learn the true total for "N of M".
	distinct := len(rows)
	if len(rows) == priorContextEndpointCap {
		var d int
		if err := repo.DB().NewSelect().
			ColumnExpr("COUNT(*)").
			TableExpr("(SELECT DISTINCT method, path FROM http_records WHERE project_uuid = ?) AS de", projectUUID).
			Scan(ctx, &d); err == nil && d > distinct {
			distinct = d
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Top endpoints (deduped by method+path; %d of %d — `query_records` for the rest):\n", len(rows), distinct)
	for _, r := range rows {
		path := r.Path
		if path == "" {
			path = "/"
		}
		fmt.Fprintf(&b, "  %-5s %-40s %3d  ×%d\n", r.Method, truncateLine(path, 40), r.Status, r.N)
	}
	return strings.TrimRight(b.String(), "\n")
}

// priorFindingList renders up to priorContextFindingCap findings (highest
// severity first), with a pointer to the rest.
func priorFindingList(ctx context.Context, repo *database.Repository, projectUUID string) string {
	var rows []struct {
		ModuleName string `bun:"module_name"`
		Severity   string `bun:"severity"`
		URL        string `bun:"url"`
		Hostname   string `bun:"hostname"`
	}
	err := repo.DB().NewSelect().
		Table("findings").
		ColumnExpr("module_name").
		ColumnExpr("severity").
		ColumnExpr("url").
		ColumnExpr("hostname").
		Where("project_uuid = ?", projectUUID).
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", database.RecordKindFinding).
		Where("(status IS NULL OR status != ?)", "false_positive").
		// Highest-severity first, matching the header's formatSeverityCounts order
		// (suspect ranks above info, per the shared severityOrder).
		OrderExpr("CASE LOWER(severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'suspect' THEN 4 WHEN 'info' THEN 5 ELSE 6 END").
		Limit(priorContextFindingCap).
		Scan(ctx, &rows)
	if err != nil || len(rows) == 0 {
		return ""
	}

	// Same as the endpoint table: the fetched rows are the full set unless capped.
	total := len(rows)
	if len(rows) == priorContextFindingCap {
		var t int
		if err := repo.DB().NewSelect().
			Table("findings").
			ColumnExpr("COUNT(*)").
			Where("project_uuid = ?", projectUUID).
			Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", database.RecordKindFinding).
			Where("(status IS NULL OR status != ?)", "false_positive").
			Scan(ctx, &t); err == nil && t > total {
			total = t
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Open findings (%d of %d — `list findings` for the rest):\n", len(rows), total)
	for _, r := range rows {
		loc := r.URL
		if loc == "" {
			loc = r.Hostname
		}
		name := r.ModuleName
		if name == "" {
			name = "(finding)"
		}
		sev := titleWord(r.Severity)
		if sev == "" {
			sev = "Info"
		}
		line := fmt.Sprintf("  [%s] %s", sev, name)
		if loc != "" {
			line += " — " + truncateLine(loc, 80)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatSeverityCounts renders " (2 High, 5 Medium, 5 Low)" highest-severity
// first, or "" when there are no findings. Ordering reuses the shared
// severityOrder (which includes suspect); keys are matched case-insensitively.
func formatSeverityCounts(counts map[string]int64) string {
	if len(counts) == 0 {
		return ""
	}
	lower := make(map[string]int64, len(counts))
	for k, v := range counts {
		lower[strings.ToLower(strings.TrimSpace(k))] += v
	}
	var parts []string
	// severityOrder is ascending (info…critical); walk it in reverse for
	// highest-first display.
	for i := len(severityOrder) - 1; i >= 0; i-- {
		if n := lower[severityOrder[i]]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, titleWord(severityOrder[i])))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// titleWord lowercases s then upper-cases its first rune (severities are single
// words, so this avoids the deprecated strings.Title).
func titleWord(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
