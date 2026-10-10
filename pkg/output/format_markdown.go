package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func GenerateMarkdownReport(items []any, outputPath string, meta HTMLReportMeta) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	_, err = f.WriteString(renderMarkdownReport(items, meta))
	return err
}

// renderMarkdownReport renders the whole Markdown report to a string. Shared by
// the markdown format and the github format's GITHUB_STEP_SUMMARY append.
func renderMarkdownReport(items []any, meta HTMLReportMeta) string {
	data := buildReportData(items, meta.Title, meta)
	w := &strings.Builder{}

	writeMarkdownHeader(w, data)
	writeMarkdownTOC(w, data)
	writeMarkdownExecutiveSummary(w, data)
	opts := newMarkdownFindingOptions(meta)
	writeMarkdownFindings(w, "Critical", data.CriticalFindings, opts)
	writeMarkdownFindings(w, "High", data.HighFindings, opts)
	writeMarkdownFindings(w, "Medium", data.MediumFindings, opts)
	writeMarkdownFindings(w, "Low", data.LowFindings, opts)
	writeMarkdownFindings(w, "Info", data.InfoFindings, opts)
	return w.String()
}

// renderMarkdownSummary renders only the report header and executive summary,
// for destinations with a size limit the full report can exceed.
func renderMarkdownSummary(items []any, meta HTMLReportMeta) string {
	data := buildReportData(items, meta.Title, meta)
	w := &strings.Builder{}
	writeMarkdownHeader(w, data)
	writeMarkdownExecutiveSummary(w, data)
	return w.String()
}

func writeMarkdownHeader(w *strings.Builder, data ReportData) {
	fmt.Fprintf(w, "# %s\n\n", data.Title)
	generated := data.GeneratedAt
	if generated == "" {
		generated = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	}
	fmt.Fprintf(w, "**Generated:** %s  \n", generated)
	if data.VigoliumVersion != "" {
		fmt.Fprintf(w, "**Vigolium Version:** %s  \n", data.VigoliumVersion)
	}
	if data.Target != "" {
		fmt.Fprintf(w, "**Target:** %s  \n", data.Target)
	}
	if data.ScanDuration != "" {
		fmt.Fprintf(w, "**Scan Duration:** %s  \n", data.ScanDuration)
	}
	w.WriteString("\n---\n\n")
}

func writeMarkdownTOC(w *strings.Builder, data ReportData) {
	w.WriteString("## Table of Contents\n\n")
	w.WriteString("- [Executive Summary](#executive-summary)\n")
	writeMarkdownTOCGroup(w, "Critical", "critical-findings", data.CriticalFindings)
	writeMarkdownTOCGroup(w, "High", "high-findings", data.HighFindings)
	writeMarkdownTOCGroup(w, "Medium", "medium-findings", data.MediumFindings)
	writeMarkdownTOCGroup(w, "Low", "low-findings", data.LowFindings)
	writeMarkdownTOCGroup(w, "Info", "info-findings", data.InfoFindings)
	w.WriteString("\n")
}

func writeMarkdownTOCGroup(w *strings.Builder, severity, anchor string, findings []ReportFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(w, "- [%s Findings (%d)](#%s)\n", severity, len(findings), anchor)
	for _, f := range findings {
		fmt.Fprintf(w, "  - [#%d %s](#%s)\n", f.ID, f.Title, findingHeadingSlug(f.ID, f.Title))
	}
}

func writeMarkdownExecutiveSummary(w *strings.Builder, data ReportData) {
	w.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(w, "A total of **%d findings** were identified during the scan.\n\n", data.TotalFindings)

	w.WriteString("| Severity | Count |\n")
	w.WriteString("|----------|-------|\n")
	if data.CriticalCount > 0 {
		fmt.Fprintf(w, "| Critical | %d |\n", data.CriticalCount)
	}
	if data.HighCount > 0 {
		fmt.Fprintf(w, "| High | %d |\n", data.HighCount)
	}
	if data.MediumCount > 0 {
		fmt.Fprintf(w, "| Medium | %d |\n", data.MediumCount)
	}
	if data.LowCount > 0 {
		fmt.Fprintf(w, "| Low | %d |\n", data.LowCount)
	}
	if data.InfoCount > 0 {
		fmt.Fprintf(w, "| Info | %d |\n", data.InfoCount)
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n", data.TotalFindings)

	w.WriteString("\n")

	if data.TotalRequests > 0 {
		fmt.Fprintf(w, "**Total HTTP Requests:** %d  \n", data.TotalRequests)
	}
	if data.ActiveModules > 0 || data.PassiveModules > 0 {
		fmt.Fprintf(w, "**Modules:** %d active, %d passive  \n", data.ActiveModules, data.PassiveModules)
	}
	w.WriteString("\n")
}

// markdownFindingOptions carries the per-report knobs the finding renderer
// needs: the shared request/response cap and the follow-up command composer.
type markdownFindingOptions struct {
	maxBodyBytes int
	followUp     func(tail ...string) string
}

func newMarkdownFindingOptions(meta HTMLReportMeta) markdownFindingOptions {
	o := markdownFindingOptions{maxBodyBytes: meta.MaxBodyBytes, followUp: meta.FollowUp}
	if o.maxBodyBytes == 0 {
		o.maxBodyBytes = DefaultMarkdownMaxBodyBytes
	}
	if o.followUp == nil {
		o.followUp = func(tail ...string) string { return "vigolium " + strings.Join(tail, " ") }
	}
	return o
}

func writeMarkdownFindings(w *strings.Builder, severity string, findings []ReportFinding, opts markdownFindingOptions) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintf(w, "## %s Findings\n\n", severity)

	for _, f := range findings {
		fmt.Fprintf(w, "### %d. %s\n\n", f.ID, f.Title)

		if f.ModuleName != "" {
			fmt.Fprintf(w, "**Module:** %s", f.ModuleName)
			if f.ModuleID != "" {
				fmt.Fprintf(w, " (%s)", MarkdownCodeSpan(f.ModuleID))
			}
			w.WriteString("  \n")
		}
		fmt.Fprintf(w, "**Severity:** %s  \n", cases.Title(language.English).String(f.Severity))
		if f.Confidence != "" {
			fmt.Fprintf(w, "**Confidence:** %s  \n", f.Confidence)
		}
		if f.CWE != "" {
			fmt.Fprintf(w, "**CWE:** %s  \n", f.CWE)
		}
		if f.CVSSScore > 0 {
			fmt.Fprintf(w, "**CVSS:** %.1f  \n", f.CVSSScore)
		}
		if f.URL != "" {
			fmt.Fprintf(w, "**URL:** %s  \n", MarkdownCodeSpan(f.URL))
		}
		if f.SourceFile != "" {
			fmt.Fprintf(w, "**Source File:** %s  \n", MarkdownCodeSpan(f.SourceFile))
		}
		if f.RepoName != "" {
			fmt.Fprintf(w, "**Repository:** %s  \n", f.RepoName)
		}
		if f.FoundAt != "" {
			fmt.Fprintf(w, "**Found At:** %s  \n", f.FoundAt)
		}
		w.WriteString("\n")

		writeMarkdownFindingMetadata(w, f, opts)

		if f.Description != "" {
			fmt.Fprintf(w, "%s\n\n", normalizeFindingBody(f.Description))
		}

		if f.Remediation != "" {
			fmt.Fprintf(w, "**Remediation:** %s\n\n", f.Remediation)
		}

		if len(f.MatchedAt) > 0 {
			w.WriteString("**Matched At:**\n")
			for _, m := range f.MatchedAt {
				fmt.Fprintf(w, "- %s\n", MarkdownCodeSpan(m))
			}
			w.WriteString("\n")
		}

		if len(f.ExtractedResults) > 0 {
			w.WriteString("**Extracted Results:**\n")
			for _, r := range f.ExtractedResults {
				fmt.Fprintf(w, "- %s\n", MarkdownCodeSpan(r))
			}
			w.WriteString("\n")
		}

		if len(f.AdditionalEvidence) > 0 {
			w.WriteString("**Additional Evidence:**\n")
			for _, e := range f.AdditionalEvidence {
				fmt.Fprintf(w, "- %s\n", e)
			}
			w.WriteString("\n")
		}

		// Request and response get the same cap: the request carries the
		// payload, so it is as much evidence as the response and must not be
		// the one left unbounded.
		writeMarkdownHTTPDetails(w, "HTTP Request", f.Request, opts.maxBodyBytes, markdownFullCommand(f, opts, true))
		writeMarkdownHTTPDetails(w, "HTTP Response", f.Response, opts.maxBodyBytes, markdownFullCommand(f, opts, false))

		if len(f.Tags) > 0 {
			fmt.Fprintf(w, "**Tags:** %s\n\n", strings.Join(f.Tags, ", "))
		}

		w.WriteString("---\n\n")
	}
}

// writeMarkdownFindingMetadata writes the identifiers that tie a finding back
// to the store — finding_id, finding_hash, scan_uuid, module_id and the linked
// record UUIDs — as a two-column table keyed by their machine names, followed
// by a ready-to-run follow-up command. Empty identifiers are omitted.
func writeMarkdownFindingMetadata(w *strings.Builder, f ReportFinding, opts markdownFindingOptions) {
	type row struct{ key, val string }
	var rows []row
	if f.ID > 0 {
		rows = append(rows, row{"finding_id", MarkdownCodeSpan(strconv.Itoa(f.ID))})
	}
	if f.FindingHash != "" {
		rows = append(rows, row{"finding_hash", MarkdownCodeSpan(f.FindingHash)})
	}
	if f.ScanUUID != "" {
		rows = append(rows, row{"scan_uuid", MarkdownCodeSpan(f.ScanUUID)})
	}
	if f.ModuleID != "" {
		rows = append(rows, row{"module_id", MarkdownCodeSpan(f.ModuleID)})
	}
	if len(f.RecordUUIDs) > 0 {
		spans := make([]string, 0, len(f.RecordUUIDs))
		for _, u := range f.RecordUUIDs {
			spans = append(spans, MarkdownCodeSpan(u))
		}
		rows = append(rows, row{"record_uuids", strings.Join(spans, ", ")})
	}
	if len(rows) == 0 {
		return
	}
	w.WriteString("| Field | Value |\n|-------|-------|\n")
	for _, r := range rows {
		// A pipe inside a cell would split the row; identifiers never carry
		// one, but escape defensively.
		fmt.Fprintf(w, "| %s | %s |\n", r.key, strings.ReplaceAll(r.val, "|", "\\|"))
	}
	w.WriteString("\n")
	if f.ID > 0 {
		if cmd := opts.followUp("finding", "--id", strconv.Itoa(f.ID)); cmd != "" {
			fmt.Fprintf(w, "**Follow-up:** %s\n\n", MarkdownCodeSpan(cmd))
		}
	}
}

// markdownFullCommand names the command that prints a truncated message whole:
// the first linked record's body when the finding has one, else the finding
// itself rendered with --full-body.
func markdownFullCommand(f ReportFinding, opts markdownFindingOptions, request bool) string {
	if len(f.RecordUUIDs) > 0 && f.RecordUUIDs[0] != "" {
		tail := []string{"traffic", "body", "--uuid", f.RecordUUIDs[0]}
		if request {
			tail = append(tail, "--request")
		}
		return opts.followUp(tail...)
	}
	if f.ID > 0 {
		return opts.followUp("finding", "--id", strconv.Itoa(f.ID), "--markdown", "--full-body")
	}
	return ""
}

// writeMarkdownHTTPDetails writes one raw HTTP message inside a collapsible
// <details> block, fenced with a backtick run longer than any inside the
// message and capped at maxBytes with an explicit truncation note.
func writeMarkdownHTTPDetails(w *strings.Builder, summary, raw string, maxBytes int, fullCmd string) {
	if raw == "" {
		return
	}
	body, note := truncateMarkdownHTTP(raw, maxBytes, fullCmd)
	body = strings.TrimRight(body, "\r\n")
	open, closeFence := MarkdownFence(body, "http")
	fmt.Fprintf(w, "<details>\n<summary>%s</summary>\n\n%s\n%s\n%s\n\n", summary, open, body, closeFence)
	if note != "" {
		fmt.Fprintf(w, "%s\n\n", note)
	}
	w.WriteString("</details>\n\n")
}

// normalizeFindingBody prepares a finding's description for embedding under the
// `### N. Title` heading: it drops a redundant leading `# ...` h1 line (common
// in audit report.md bodies, where the title is restated as h1) and demotes
// all remaining headings by 2 levels so they sit cleanly below h3 (e.g.
// `## Summary` → `#### Summary`).
func normalizeFindingBody(body string) string {
	body = stripLeadingH1(body)
	body = demoteHeadings(body, 2)
	return body
}

// stripLeadingH1 removes a leading `# ...` ATX heading from body, along with
// any preceding blank lines. Returns body unchanged if the first non-blank
// line isn't an h1.
func stripLeadingH1(body string) string {
	trimmed := strings.TrimLeft(body, " \t\r\n")
	if !strings.HasPrefix(trimmed, "# ") {
		return body
	}
	nl := strings.IndexByte(trimmed, '\n')
	if nl == -1 {
		return ""
	}
	return strings.TrimLeft(trimmed[nl+1:], "\r\n")
}

// findingHeadingSlug computes the GitHub-flavored auto-anchor for a heading of
// the form `### {id}. {title}`. It mirrors the slug rules used by VS Code's
// markdown preview and GitHub: lowercase, drop punctuation other than hyphens
// and underscores, collapse whitespace to single hyphens.
func findingHeadingSlug(id int, title string) string {
	text := fmt.Sprintf("%d. %s", id, title)
	text = strings.ToLower(text)
	var b strings.Builder
	b.Grow(len(text))
	prevHyphen := false
	for _, r := range text {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
			prevHyphen = false
		case r == '-':
			b.WriteRune(r)
			prevHyphen = true
		case r == ' ' || r == '\t':
			if !prevHyphen {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// demoteHeadings shifts every ATX heading (`#`, `##`, ...) down by `levels`,
// capped at h6. Headings inside fenced code blocks (``` or ~~~) are left alone.
func demoteHeadings(body string, levels int) string {
	if levels <= 0 || body == "" {
		return body
	}
	lines := strings.Split(body, "\n")
	inFence := false
	fence := ""
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if inFence {
			if strings.HasPrefix(trimmed, fence) {
				inFence = false
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			inFence = true
			fence = "```"
			continue
		}
		if strings.HasPrefix(trimmed, "~~~") {
			inFence = true
			fence = "~~~"
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		hashes := 0
		for hashes < len(trimmed) && trimmed[hashes] == '#' {
			hashes++
		}
		if hashes == 0 || hashes > 6 {
			continue
		}
		if hashes == len(trimmed) || (trimmed[hashes] != ' ' && trimmed[hashes] != '\t') {
			continue
		}
		newLevel := hashes + levels
		if newLevel > 6 {
			newLevel = 6
		}
		indent := line[:len(line)-len(trimmed)]
		lines[i] = indent + strings.Repeat("#", newLevel) + trimmed[hashes:]
	}
	return strings.Join(lines, "\n")
}
