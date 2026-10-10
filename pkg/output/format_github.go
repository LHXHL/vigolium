package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// reportStdout is where a report rendered without an output path goes (the
// github format). A variable so tests can capture it.
var reportStdout io.Writer = os.Stdout

// githubStepSummaryLimit is GitHub's per-step job-summary cap (1 MiB). The full
// Markdown report is appended only when it fits under this with some headroom
// for other steps' content; otherwise the summary-only rendering is used.
const githubStepSummaryLimit = 1<<20 - 64<<10

// GenerateGitHubAnnotations writes one GitHub Actions workflow command per
// finding — ::error for critical/high, ::warning for medium/low, ::notice for
// info/suspect — so findings show up as annotations on the run. Dismissed
// findings (false_positive, accepted_risk) are left out. file= (and line=) are
// set only for code findings that carry a source file; HTTP findings name their
// URL in the message.
//
// An empty outputPath (no -o) writes to stdout, which is where the Actions
// runner reads workflow commands from; any other path writes a file. When
// GITHUB_STEP_SUMMARY is set, the Markdown report is appended to it as well.
func GenerateGitHubAnnotations(items []any, outputPath string, meta HTMLReportMeta) error {
	findings := collectFindingViews(items)
	render := func(w io.Writer) error { return writeGitHubAnnotations(w, findings) }
	if outputPath == "" {
		bw := bufio.NewWriter(reportStdout)
		if err := render(bw); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	} else if err := writeReportFile(outputPath, render); err != nil {
		return err
	}
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		if err := appendGitHubStepSummary(summary, items, meta); err != nil {
			return fmt.Errorf("append GITHUB_STEP_SUMMARY: %w", err)
		}
	}
	return nil
}

func writeGitHubAnnotations(w io.Writer, findings []FindingView) error {
	live := findings[:0:0]
	for _, f := range findings {
		if !isDismissedStatus(f.Status) {
			live = append(live, f)
		}
	}
	sort.SliceStable(live, func(i, j int) bool {
		si, sj := severity.ToSeverity(live[i].Severity), severity.ToSeverity(live[j].Severity)
		if si != sj {
			return si > sj
		}
		return live[i].FindingHash < live[j].FindingHash
	})
	for _, f := range live {
		if _, err := io.WriteString(w, githubAnnotation(f)+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// githubLevel maps a severity onto a workflow-command level.
func githubLevel(sev string) string {
	switch severity.ToSeverity(sev) {
	case severity.Critical, severity.High:
		return "error"
	case severity.Medium, severity.Low:
		return "warning"
	default:
		return "notice"
	}
}

func githubAnnotation(f FindingView) string {
	var props []string
	if f.SourceFile != "" {
		file, line, col := splitSourceRef(strings.TrimSpace(f.SourceFile))
		if file != "" {
			props = append(props, "file="+githubEscapeProperty(sarifSourceURI(file, f.RepoName)))
			if line > 0 {
				props = append(props, "line="+strconv.Itoa(line))
				if col > 0 {
					props = append(props, "col="+strconv.Itoa(col))
				}
			}
		}
	}
	title := fmt.Sprintf("[%s] %s", f.Severity, f.Name())
	props = append(props, "title="+githubEscapeProperty(title))

	// The message names the finding by the finding view's keys, so each handle
	// is what `vigolium finding` takes (--id, a finding_hash prefix).
	var msg strings.Builder
	msg.WriteString(f.Name())
	if f.URL != "" {
		msg.WriteString(" at ")
		msg.WriteString(f.URL)
	}
	var ids []string
	if f.FindingHash != "" {
		ids = append(ids, "finding_hash "+shortHash(f.FindingHash))
	}
	if f.ID > 0 {
		ids = append(ids, "id "+strconv.FormatInt(f.ID, 10))
	}
	if f.ModuleID != "" {
		ids = append(ids, "module_id "+f.ModuleID)
	}
	if len(ids) > 0 {
		msg.WriteString(" (" + strings.Join(ids, ", ") + ")")
	}
	return "::" + githubLevel(f.Severity) + " " + strings.Join(props, ",") + "::" + githubEscapeData(msg.String())
}

// githubEscapeData escapes a workflow-command message: '%', CR and LF.
func githubEscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

// githubEscapeProperty escapes a workflow-command property value: the data
// escapes plus ':' and ',', which delimit properties.
func githubEscapeProperty(s string) string {
	s = githubEscapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	return strings.ReplaceAll(s, ",", "%2C")
}

// appendGitHubStepSummary appends the Markdown report to the job summary file,
// falling back to the header and executive summary when the full report would
// exceed GitHub's step-summary limit.
func appendGitHubStepSummary(path string, items []any, meta HTMLReportMeta) error {
	body := renderMarkdownReport(items, meta)
	if len(body) > githubStepSummaryLimit {
		body = renderMarkdownSummary(items, meta) +
			fmt.Sprintf("_Full report omitted: %d bytes exceeds the job-summary limit; render it with `--format markdown -o <file>`._\n", len(body))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(body + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
