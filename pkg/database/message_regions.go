package database

import "fmt"

// Header/body attribution for searches over the stored raw HTTP corpus.
//
// --header and --body used to be the same query. Both called
// applyRawCorpusSearch, which scans raw_request/raw_response whole — and those
// columns hold the entire message, headers AND body. So on a seeded store
// `--header password` returned three records whose only "password" was in a
// response body, and `--body Authorization` returned sixteen whose only
// "Authorization" was a request header name. The flags promised a location and
// delivered a corpus.
//
// The fix splits the message in SQL rather than in Go. Filtering the rows after
// they are fetched would give the same answer for a page but not for `total`,
// `--limit` or `--offset`: the count comes from ScanAndCount over the predicate,
// so a Go-side refinement produces a page of twelve rows reporting a total of a
// hundred. Attribution has to be part of the predicate or it is not part of the
// query.
//
// `--search` is unchanged and remains the whole-exchange search; it is
// documented as spanning headers + body and is the right flag when the location
// does not matter.

// The blank line that ends a header block. A stored message uses CRLF, but
// anything ingested from a proxy, a fixture or a hand-written request file may
// use bare LF, and splitHeadersBody in the CLI accepts both — so the SQL does
// too. Whichever appears FIRST is the real separator: a CRLF message whose body
// contains "\n\n" would otherwise be split inside its body.
const (
	sqlCRLFCRLF = "char(13)||char(10)||char(13)||char(10)"
	sqlLFLF     = "char(10)||char(10)"
	pgCRLFCRLF  = "chr(13)||chr(10)||chr(13)||chr(10)"
	pgLFLF      = "chr(10)||chr(10)"
)

// messageDialect carries the per-driver spellings of the string functions this
// file needs. Postgres names two of them differently and is 1-based like SQLite,
// so only the names change.
type messageDialect struct {
	indexOf string // 1-based offset of arg2 in arg1, or 0
	minOf   string // smallest of its arguments
	crlfLF  string
	lfLF    string
}

func dialectFor(driver string) messageDialect {
	if driver == "postgres" {
		return messageDialect{indexOf: "strpos", minOf: "least", crlfLF: pgCRLFCRLF, lfLF: pgLFLF}
	}
	return messageDialect{indexOf: "instr", minOf: "min", crlfLF: sqlCRLFCRLF, lfLF: sqlLFLF}
}

// noBlankLine stands in for "not found" when taking the minimum of the two
// candidate offsets. It is larger than any message this store holds, so it never
// wins the min, and it doubles as the header length for a message with no blank
// line at all — which is what makes the CASE below unnecessary.
const noBlankLine = "9223372036854775807"

// blankLineExpr renders the 1-based offset of the first blank line in text, or
// noBlankLine when there is none. `text` must be a SQL expression yielding TEXT.
//
// Each candidate offset is computed ONCE and a scalar min picks the earlier one.
// The obvious spelling — a CASE comparing the two — mentions each instr() twice
// and the whole expression again per branch, and neither SQLite nor Postgres
// eliminates common subexpressions here: every textual occurrence re-reads the
// blob and re-scans it end to end. On the full scan that --header/--body already
// force, that difference is the query's whole cost.
//
// Zero means "not found", so it is mapped to noBlankLine before the min; a bare
// min would always choose the zero.
func (d messageDialect) blankLineExpr(text string) string {
	offset := func(sep string) string {
		return fmt.Sprintf("COALESCE(NULLIF(%s(%s, %s), 0), %s)", d.indexOf, text, sep, noBlankLine)
	}
	return fmt.Sprintf("%s(%s, %s)", d.minOf, offset(d.crlfLF), offset(d.lfLF))
}

// headerRegion renders the header block of a raw message: everything before the
// first blank line.
//
// A message with no blank line at all is treated as headers only. That is the
// right reading for a truncated capture and for a response recorded with no
// body, and it keeps a header search from silently skipping those rows — and it
// falls out of noBlankLine for free, since substr past the end of a string
// simply returns the rest of it.
func (d messageDialect) headerRegion(text string) string {
	return fmt.Sprintf("substr(%s, 1, %s - 1)", text, d.blankLineExpr(text))
}

// bodyRegion renders the body of a raw message: everything from the first blank
// line on, and the empty string when there is no blank line.
//
// The separator itself is deliberately left at the front of the region rather
// than skipped. Skipping it would mean knowing whether it was two bytes or four,
// which doubles every expression here for no gain: a search term would have to
// contain a CRLF pair to be confused by the two or four leading bytes, and a
// command-line search term does not.
func (d messageDialect) bodyRegion(text string) string {
	return fmt.Sprintf("substr(%s, %s)", text, d.blankLineExpr(text))
}

// rawText renders a raw_* blob column as TEXT, matching what the LIKE
// predicates elsewhere in this package do.
func rawText(col string) string { return fmt.Sprintf("CAST(%s AS TEXT)", col) }

// regionPredicate builds a two-placeholder predicate matching a term inside one
// region (headers or body) of EITHER the request or the response — the same
// request-or-response reach the whole-corpus search has, narrowed to one part of
// each message.
//
// COALESCE guards the NULL case so the negated form used by --exclude-* stays
// NULL-safe, for the reason spelled out above recordSearchPredicate.
func regionPredicate(region func(string) string) string {
	return WithLikeEscape(fmt.Sprintf(
		"(COALESCE(%s, '') LIKE ? OR COALESCE(%s, '') LIKE ?)",
		region(rawText("r.raw_request")), region(rawText("r.raw_response"))))
}

// headerSearchPredicate and bodySearchPredicate are the two predicates
// --header/--body use. Two ? placeholders each; prefix "NOT " for the
// --exclude-* forms.
func headerSearchPredicate(driver string) string {
	return regionPredicate(dialectFor(driver).headerRegion)
}

func bodySearchPredicate(driver string) string {
	return regionPredicate(dialectFor(driver).bodyRegion)
}

// findingRegionPredicate lifts a record predicate through the finding_records
// junction: a finding matches when any record it links to does. It keeps the
// placeholder count of the predicate it wraps, and prefixing "NOT " turns it
// into the --exclude-* form.
//
// EXISTS, never a JOIN: a finding linked to N records on the matching host must
// yield ONE row, not N — a JOIN there duplicated both the listed rows and the
// ScanAndCount total.
//
// Every findings-side record filter goes through here — host, path, method,
// status, source and the region searches — so the junction's shape is defined
// once. It used to be spelled out at each of those call sites, which is six
// chances for one of them to be JOINed by mistake.
func findingRegionPredicate(recordPredicate string) string {
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM finding_records fr2
		INNER JOIN http_records r ON r.uuid = fr2.record_uuid
		WHERE fr2.finding_id = f.id AND %s)`, recordPredicate)
}
