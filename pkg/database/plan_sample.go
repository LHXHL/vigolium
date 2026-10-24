package database

import (
	"context"
	"fmt"
	"strings"
)

// InsertionPointSample summarizes a sample of stored records for the scan
// plan's request estimate: how many records were read, and how many
// parameters and path segments an average one carries (each is an insertion
// point an active module may test).
type InsertionPointSample struct {
	Records         int
	AvgParams       float64
	AvgPathSegments float64
}

// SampleInsertionPoints reads at most limit records of the project on the
// given in-scope origins (empty = every origin) — the parameters and path
// columns only, never a body — and averages their insertion points.
// Read-only.
func (r *Repository) SampleInsertionPoints(ctx context.Context, projectUUID string, hosts []HostTarget, limit int) (InsertionPointSample, error) {
	if limit <= 0 {
		limit = 1000
	}
	// Only the parameter count is needed, so SQL measures the JSON array
	// instead of every row's parameters being decoded. parameters is TEXT on
	// both drivers; NULL, '' and a non-array count as no parameters.
	paramCount := "CASE WHEN parameters IS NULL OR parameters = '' THEN 0 ELSE json_array_length(parameters) END"
	if r.db.Driver() == driverPostgres {
		paramCount = "CASE WHEN parameters IS NULL OR parameters = '' THEN 0" +
			" WHEN jsonb_typeof(parameters::jsonb) = 'array' THEN jsonb_array_length(parameters::jsonb) ELSE 0 END"
	}
	var rows []struct {
		ParamCount int    `bun:"param_count"`
		Path       string `bun:"path"`
	}
	q := r.db.NewSelect().Model((*HTTPRecord)(nil)).ColumnExpr(paramCount + " AS param_count").Column("path")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	q = applyHostScopeFilter(q, hosts)
	if err := q.Limit(int64(limit)).Scan(ctx, &rows); err != nil {
		return InsertionPointSample{}, fmt.Errorf("sample records: %w", err)
	}
	var s InsertionPointSample
	if len(rows) == 0 {
		return s, nil
	}
	var params, segments int
	for _, rec := range rows {
		params += rec.ParamCount
		for _, seg := range strings.Split(strings.Trim(rec.Path, "/"), "/") {
			if seg != "" {
				segments++
			}
		}
	}
	s.Records = len(rows)
	s.AvgParams = float64(params) / float64(len(rows))
	s.AvgPathSegments = float64(segments) / float64(len(rows))
	return s, nil
}
