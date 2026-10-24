package csv_formula_injection

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"path"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	// maxBodyBytes bounds how much of an export is inspected.
	maxBodyBytes = 8 << 20
	// maxRecords bounds the CSV rows parsed.
	maxRecords = 50000
	// maxSheetBytes bounds the decompressed size read from one XLSX sheet.
	maxSheetBytes = 16 << 20
	// maxReported caps the cells listed in one finding.
	maxReported = 5
)

// triggerChars start a cell that spreadsheet applications evaluate as a
// formula (OWASP CSV injection list).
const triggerChars = "=+-@\t\r"

// cellPreviewRunes caps the offending cell text quoted in a finding.
const cellPreviewRunes = 120

var (
	// scanCanaryRe matches the canary tokens vigolium's active modules plant
	// (modkit.FreshCanary "vigolium"+10 hex, xss_stored "vigolium-sx-"+12 hex), so a
	// stored probe value surfacing unescaped in an export is attributable.
	scanCanaryRe = regexp.MustCompile(`vigolium[0-9a-f]{10}|vigolium-sx-[0-9a-f]{12}`)
	// functionCallRe matches a formula body that opens with a function call
	// (no space before the parenthesis, so prose like "- see (note)" passes).
	functionCallRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\(`)
	// ddeRe matches a DDE command (cmd|' /C calc'!A0, msexcel|...).
	ddeRe = regexp.MustCompile(`^[A-Za-z0-9_.]+\s*\|`)
	// externalFuncRe names the functions that reach outside the workbook or
	// run code; in an XLSX these are flagged even without a canary.
	externalFuncRe = regexp.MustCompile(`(?i)\b(WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|FILTERXML|CALL|REGISTER|EXEC|DDE|DDEAUTO)\s*\(`)
	// dangerousFuncRe is externalFuncRe plus the link/image functions, which a
	// CSV generator never legitimately writes.
	dangerousFuncRe = regexp.MustCompile(`(?i)\b(HYPERLINK|IMAGE|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|FILTERXML|CALL|REGISTER|EXEC|DDE|DDEAUTO)\s*\(`)
	// formulaRe extracts XLSX <f> formula elements.
	formulaRe = regexp.MustCompile(`<f(?:\s[^>]*)?>([^<]*)</f>`)
	// sheetRe matches worksheet parts inside an XLSX package.
	sheetRe = regexp.MustCompile(`^xl/worksheets/[^/]+\.xml$`)
)

// csvContentTypes are the media types of CSV exports.
var csvContentTypes = []string{"text/csv", "application/csv", "text/comma-separated-values", "text/x-csv", "application/x-csv"}

const xlsxContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

// Module implements the CSV / formula injection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSV / formula injection module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_csv_formula_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// hit is one flagged cell.
type hit struct {
	where  string
	cell   string
	reason string
	sev    severity.Severity
	conf   severity.Confidence
}

// ScanPerRequest inspects CSV/XLSX export responses for formula cells.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	resp := ctx.Response()
	if resp == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	kind := exportKind(resp.Header("Content-Type"), resp.Header("Content-Disposition"), urlx.Path)
	if kind == "" {
		return nil, nil
	}
	body := resp.Body()
	if len(body) == 0 {
		return nil, nil
	}
	if len(body) > maxBodyBytes {
		if kind == "xlsx" {
			return nil, nil // a truncated zip has no central directory
		}
		body = body[:maxBodyBytes]
	}

	var hits []hit
	if kind == "xlsx" {
		hits = scanXLSX(body)
	} else {
		hits = scanCSV(body)
	}
	if len(hits) == 0 {
		return nil, nil
	}

	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil && ds.IsSeen(utils.Sha1(urlx.Host+urlx.Path)) {
		return nil, nil
	}

	best := hits[0]
	for _, h := range hits[1:] {
		if h.sev > best.sev || (h.sev == best.sev && h.conf > best.conf) {
			best = h
		}
	}
	extracted := make([]string, 0, maxReported)
	for i, h := range hits {
		if i == maxReported {
			break
		}
		extracted = append(extracted, fmt.Sprintf("%s: %q (%s)", h.where, h.cell, h.reason))
	}
	return []*output.ResultEvent{{
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: extracted,
		Info: output.Info{
			Name: ModuleName,
			Description: fmt.Sprintf("The %s export contains %d cell(s) a spreadsheet application evaluates as a formula; "+
				"the strongest is %s at %s. Values starting with = + - @ tab or carriage return are not escaped.",
				strings.ToUpper(kind), len(hits), best.reason, best.where),
			Severity:   best.sev,
			Confidence: best.conf,
		},
		Metadata: map[string]any{"format": kind, "formula_cells": len(hits)},
	}}, nil
}

// exportKind classifies a response as a "csv" or "xlsx" export, or "".
func exportKind(contentType, disposition, urlPath string) string {
	ct := strings.ToLower(contentType)
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		ct = mt
	}
	for _, c := range csvContentTypes {
		if ct == c {
			return "csv"
		}
	}
	if ct == xlsxContentType {
		return "xlsx"
	}
	if disposition == "" {
		return ""
	}
	dispType, params, err := mime.ParseMediaType(disposition)
	if err != nil || !strings.EqualFold(dispType, "attachment") {
		return ""
	}
	name := params["filename"]
	if name == "" {
		name = path.Base(urlPath)
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".csv":
		return "csv"
	case ".xlsx":
		return "xlsx"
	}
	return ""
}

// scanCSV parses the export and flags formula cells.
func scanCSV(body []byte) []hit {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(body))
	r.Comma = sniffDelimiter(body)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	r.ReuseRecord = true

	var hits []hit
	for row := 1; row <= maxRecords; row++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			var perr *csv.ParseError
			if errors.As(err, &perr) {
				continue
			}
			break
		}
		for col, cell := range rec {
			if reason, sev, conf, ok := classifyCSVCell(cell); ok {
				hits = append(hits, hit{where: fmt.Sprintf("row %d col %d", row, col+1), cell: modkit.TruncateRunes(cell, cellPreviewRunes, "…"), reason: reason, sev: sev, conf: conf})
			}
		}
	}
	return hits
}

// classifyCSVCell reports whether a CSV cell is an unescaped formula and how
// strong the signal is: a scan canary proves user input reached the export
// (Firm); a DDE command or an external/link function is dangerous on its own;
// any other function call is a weaker formula signal. Plain values that only
// happen to start with a trigger ("-12.50", "+1 555 0100", "@handle") pass.
func classifyCSVCell(cell string) (string, severity.Severity, severity.Confidence, bool) {
	if cell == "" || !strings.ContainsRune(triggerChars, rune(cell[0])) {
		return "", 0, 0, false
	}
	// Spaces are not stripped: "- item(x)" is a bullet, "-item(x)" a formula.
	body := strings.TrimLeft(cell, triggerChars)
	isFormula := functionCallRe.MatchString(body) || ddeRe.MatchString(body)
	switch {
	case scanCanaryRe.MatchString(cell):
		return "scan canary in a formula-trigger cell", severity.Medium, severity.Firm, true
	case ddeRe.MatchString(body):
		return "DDE command", severity.Medium, severity.Tentative, true
	case isFormula && dangerousFuncRe.MatchString(body):
		return "external/link formula function", severity.Medium, severity.Tentative, true
	case isFormula:
		return "formula function call", severity.Low, severity.Tentative, true
	}
	return "", 0, 0, false
}

// scanXLSX flags formula (<f>) cells in an XLSX package. String cells are
// never evaluated, so only stored formulas count, and only those carrying a
// canary, a DDE command or an external-data function: report workbooks
// routinely contain SUM or HYPERLINK formulas the application wrote itself.
func scanXLSX(body []byte) []hit {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil
	}
	var hits []hit
	for _, f := range zr.File {
		if !sheetRe.MatchString(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, maxSheetBytes))
		_ = rc.Close()
		sheet := strings.TrimSuffix(path.Base(f.Name), ".xml")
		for _, m := range formulaRe.FindAllSubmatch(data, -1) {
			formula := html.UnescapeString(string(m[1]))
			var reason string
			sev, conf := severity.Medium, severity.Tentative
			switch {
			case scanCanaryRe.MatchString(formula):
				reason, conf = "scan canary in a formula cell", severity.Firm
			case ddeRe.MatchString(formula):
				reason = "DDE command"
			case externalFuncRe.MatchString(formula):
				reason = "external-data formula function"
			default:
				continue
			}
			hits = append(hits, hit{where: sheet, cell: modkit.TruncateRunes("="+formula, cellPreviewRunes, "…"), reason: reason, sev: sev, conf: conf})
		}
	}
	return hits
}

// sniffDelimiter picks the most frequent of , ; and tab on the first line.
func sniffDelimiter(body []byte) rune {
	line := body
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		line = body[:i]
	}
	best, bestN := ',', bytes.Count(line, []byte{','})
	for _, d := range []rune{';', '\t'} {
		if n := bytes.Count(line, []byte(string(d))); n > bestN {
			best, bestN = d, n
		}
	}
	return best
}
