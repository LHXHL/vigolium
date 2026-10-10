package cli

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/output"
)

// Report-rendering knobs shared by every command that renders a report from the
// format table: the scan commands (scan, run, scan-url, scan-request), export
// and import. One registration so the help text cannot diverge between them.
//
// The defaults hold for commands that render without registering the flags
// (the REST server's post-scan reports).
var (
	reportMaxBodyBytes = output.DefaultMarkdownMaxBodyBytes
	reportPDFTimeout   time.Duration
)

// registerReportFlags declares --max-body-bytes and --pdf-timeout.
func registerReportFlags(flags *pflag.FlagSet) {
	flags.IntVar(&reportMaxBodyBytes, "max-body-bytes", output.DefaultMarkdownMaxBodyBytes,
		"Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap")
	flags.DurationVar(&reportPDFTimeout, "pdf-timeout", 0,
		fmt.Sprintf("Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else %s)", output.DefaultPDFTimeout))
}

// validateReportFlags rejects knob values no renderer can honour.
func validateReportFlags() error {
	if reportPDFTimeout < 0 {
		return usageErrorf("--pdf-timeout must not be negative, got %s", reportPDFTimeout)
	}
	return nil
}

// applyReportFlags copies the report knobs into meta: the Markdown body cap,
// the PDF timeout, the --fail-on threshold the junit format fails at, and the
// follow-up composer that pins report follow-ups to this run's --db/project.
//
// discardedStore says the report renders from a database deleted when the
// command exits (a stateless scan's temp DB). No follow-up command can reopen
// it, so follow-ups are suppressed rather than pointed at a store that is gone
// (or, bare, at the default store, where the same finding id names another row).
func applyReportFlags(meta *output.HTMLReportMeta, discardedStore bool) {
	meta.MaxBodyBytes = reportMaxBodyBytes
	if reportMaxBodyBytes <= 0 {
		meta.MaxBodyBytes = -1
	}
	meta.PDFTimeout = reportPDFTimeout
	meta.FailOn = scanFailOn
	meta.FollowUp = followUpQuery
	if discardedStore {
		meta.FollowUp = func(...string) string { return "" }
	}
}
