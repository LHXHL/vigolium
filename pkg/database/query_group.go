package database

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"
)

// Grouped counts over the SAME filter set a listing would use.
//
// The question "how many records share a status / a content type / a host" was
// previously answerable only by materializing every matching row and counting it
// in the caller — a Python Counter over a dumped export, or hand-written SQL
// against the physical schema. Both were recorded repeatedly across the
// engagement corpus this was built from, and both have the same two defects: the
// whole result set has to cross the process boundary to answer a question whose
// answer is a dozen integers, and the grouping is computed against a row set the
// caller re-derived rather than the one `traffic` would have shown.
//
// So the aggregate runs in SQL, through QueryBuilder.applyFilters — the single
// predicate set every other record read goes through. `--group-by status_code`
// therefore describes exactly the rows the same command without it would list.

// RecordGroup is one bucket: a column value and how many records carry it.
type RecordGroup struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// RecordGrouping is a bounded answer, and says so.
//
// A grouping is not automatically small — one recorded case grouped 56 rows into
// 54 distinct buckets, which is a listing wearing a summary's name. Reporting
// only the top N without saying what was left out turns that into a wrong
// answer, so the tail is counted rather than dropped.
type RecordGrouping struct {
	// Field is the public name that was grouped on, echoed back.
	Field string `json:"field"`
	// Groups are the largest buckets first, at most the requested limit.
	Groups []RecordGroup `json:"groups"`
	// DistinctGroups is how many buckets exist in total, whatever Groups holds.
	DistinctGroups int64 `json:"distinct_groups"`
	// TotalRecords is how many records the filters matched, whatever was bucketed.
	TotalRecords int64 `json:"total_records"`
	// OtherGroups / OtherRecords describe the tail beyond the limit. Both zero
	// means the grouping is complete.
	OtherGroups  int64 `json:"other_groups"`
	OtherRecords int64 `json:"other_records"`
}

// groupableColumns maps a PUBLIC field name to its physical column.
//
// A closed table, not a pass-through. Two reasons, and neither is paranoia about
// this particular call site: the value becomes a SQL identifier, and a public
// interface that accepts physical column names makes the storage schema part of
// the contract — the very coupling that had callers guessing `host` for a column
// actually named `hostname` and writing a join to recover from it. The public
// name is the one the -j record view already uses, so a field that can be read
// can be grouped by the same spelling.
var groupableColumns = map[string]string{
	"method":                "method",
	"status_code":           "status_code",
	"host":                  "hostname",
	"response_content_type": "response_content_type",
	"source":                "source",
	"scan_uuid":             "scan_uuid",
	"ip":                    "ip",
	"is_authenticated":      "is_authenticated",
}

// GroupableFields lists the accepted --group-by names, sorted, for help text and
// for the error a rejected name produces.
func GroupableFields() []string {
	out := make([]string, 0, len(groupableColumns))
	for name := range groupableColumns {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// GroupRecordsByField resolves a public field name to its physical column, or
// explains what the accepted names are.
//
// Exported so the CLI can reject a bad --group-by before it opens a database:
// a name typo is knowable from the flags alone, and finding out after the open
// is how a read command comes to touch a file it had no business touching.
func GroupRecordsByField(field string) (string, error) {
	column, ok := groupableColumns[strings.ToLower(strings.TrimSpace(field))]
	if !ok {
		return "", fmt.Errorf("cannot group by %q; supported fields: %s",
			field, strings.Join(GroupableFields(), ", "))
	}
	return column, nil
}

// GroupRecordsBy counts the filtered records by one column, largest bucket
// first, capped at limit (<= 0 means no cap).
//
// The totals come from a second query ONLY when the cap actually bit. Summing
// the returned buckets describes the whole result exactly when every bucket came
// back — each filtered row lands in exactly one bucket, since COALESCE removes
// the NULL/empty split — and describes only the visible part otherwise, which is
// how a bounded view comes to report a complete-looking number that is wrong. So
// the expensive case is paid for and the common one is not: the filters here are
// the listing's filters, which include `LIKE '%…%'` over the raw request/response
// corpus, and running those twice reads every matched record's blobs twice to
// produce a dozen integers.
func (qb *QueryBuilder) GroupRecordsBy(ctx context.Context, field string, limit int) (RecordGrouping, error) {
	field = strings.ToLower(strings.TrimSpace(field))
	column, err := GroupRecordsByField(field)
	if err != nil {
		return RecordGrouping{}, err
	}

	out := RecordGrouping{Field: field}

	// A NULL and an empty string are the same fact to a reader counting buckets
	// ("this record does not carry the value"), and splitting them produces two
	// buckets whose difference nothing downstream can act on. CAST keeps a
	// numeric column (status_code) comparable as a map key across both drivers.
	keyExpr := "COALESCE(CAST(? AS TEXT), '')"

	var rows []struct {
		Key   string `bun:"key"`
		Count int64  `bun:"count"`
	}
	q := qb.db.NewSelect().Model((*HTTPRecord)(nil)).
		ColumnExpr(keyExpr+" AS key, COUNT(*) AS count", bun.Ident(column))
	qb.applyFilters(q)
	q = q.GroupExpr(keyExpr, bun.Ident(column)).OrderExpr("count DESC, key ASC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return RecordGrouping{}, err
	}
	out.Groups = make([]RecordGroup, 0, len(rows))
	var counted int64
	for _, r := range rows {
		out.Groups = append(out.Groups, RecordGroup{Value: r.Key, Count: r.Count})
		counted += r.Count
	}

	// Fewer rows back than the LIMIT (or no LIMIT at all) means every bucket is
	// present, and the sum above IS the unbounded total.
	if limit <= 0 || len(rows) < limit {
		out.TotalRecords = counted
		out.DistinctGroups = int64(len(out.Groups))
		return out, nil
	}

	var totals struct {
		Records int64 `bun:"records"`
		Groups  int64 `bun:"groups"`
	}
	tq := qb.db.NewSelect().Model((*HTTPRecord)(nil)).
		ColumnExpr("COUNT(*) AS records, COUNT(DISTINCT "+keyExpr+") AS groups", bun.Ident(column))
	qb.applyFilters(tq)
	if err := tq.Scan(ctx, &totals); err != nil {
		return RecordGrouping{}, err
	}
	out.TotalRecords = totals.Records
	out.DistinctGroups = totals.Groups
	// Clamped because the two queries are not in one transaction: a concurrent
	// scan writing rows between them can make the later totals smaller than what
	// the first query already counted, and a negative "tail" is worse than none.
	out.OtherGroups = max(0, totals.Groups-int64(len(out.Groups)))
	out.OtherRecords = max(0, totals.Records-counted)
	return out, nil
}
