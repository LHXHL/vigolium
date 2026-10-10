package output

import (
	"bufio"
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/internal/atomicfile"
)

// SafeCSVWriter is the one CSV writer behind every CSV vigolium emits (the
// findings report and `db export --format csv`). It is encoding/csv — so commas,
// quotes, CR and LF inside a field are quoted correctly — plus a formula-
// injection guard: scanned content (a URL, a path, a response-derived title)
// that a spreadsheet would evaluate as a formula is neutralized first.
type SafeCSVWriter struct {
	w *csv.Writer
}

// NewSafeCSVWriter wraps w. Call Flush (and check its error) when done.
func NewSafeCSVWriter(w io.Writer) *SafeCSVWriter {
	return &SafeCSVWriter{w: csv.NewWriter(w)}
}

// Write writes one row, guarding every field with SanitizeCSVField.
func (s *SafeCSVWriter) Write(record []string) error {
	safe := make([]string, len(record))
	for i, field := range record {
		safe[i] = SanitizeCSVField(field)
	}
	return s.w.Write(safe)
}

// Flush flushes buffered rows and reports any write error.
func (s *SafeCSVWriter) Flush() error {
	s.w.Flush()
	return s.w.Error()
}

// SanitizeCSVField prefixes a single quote to a field a spreadsheet would treat
// as a formula: one starting with '=', '+', '-', '@', TAB or CR (the OWASP CSV
// injection set). The quote makes Excel, LibreOffice and Sheets show the value
// as text; a reader parsing the CSV programmatically sees one extra leading
// character on those fields only.
func SanitizeCSVField(field string) string {
	if field == "" {
		return field
	}
	switch field[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + field
	}
	return field
}

// FindingCSVColumns is the header of the findings CSV, in column order. Every
// column is a key of the finding view `vigolium finding -j` prints and carries
// the same value, so a column means the same thing here as there.
var FindingCSVColumns = []string{
	"id", "finding_hash", "severity", "confidence", "module_id", "module_name",
	"short", "url", "hostname", "matched_at", "scan_uuid", "http_record_uuids",
	"status", "cwe_id", "source_file", "repo_name", "found_at",
}

// GenerateCSVReport writes the findings of an export item set as CSV, one row
// per finding in item order. Multi-valued cells (matched_at,
// http_record_uuids) are joined with "; ".
func GenerateCSVReport(items []any, outputPath string, meta HTMLReportMeta) error {
	findings := collectFindingViews(items)
	return writeReportFile(outputPath, func(w io.Writer) error {
		return writeFindingsCSV(w, findings)
	})
}

func writeFindingsCSV(w io.Writer, findings []FindingView) error {
	cw := NewSafeCSVWriter(w)
	if err := cw.Write(FindingCSVColumns); err != nil {
		return err
	}
	for _, f := range findings {
		id := ""
		if f.ID > 0 {
			id = strconv.FormatInt(f.ID, 10)
		}
		row := []string{
			id,
			f.FindingHash,
			f.Severity,
			f.Confidence,
			f.ModuleID,
			f.ModuleName,
			f.Short,
			f.URL,
			f.Hostname,
			strings.Join(f.MatchedAt, "; "),
			f.ScanUUID,
			strings.Join(f.HTTPRecordUUIDs, "; "),
			f.Status,
			f.CWEID,
			f.SourceFile,
			f.RepoName,
			f.FoundAt,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Flush()
}

// writeReportFile stages a report through atomicfile so a failed render never
// leaves a truncated file a consumer cannot tell from a complete one.
func writeReportFile(outputPath string, render func(io.Writer) error) error {
	return atomicfile.WriteFile(outputPath, 0o666, func(w *bufio.Writer) error {
		return render(w)
	})
}
