package database

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// ScanHeartbeat is one liveness beat of a running scan, written onto its row.
type ScanHeartbeat struct {
	At time.Time
	// Phase is the phase running now; "" between phases (and on the final beat)
	// clears current_phase.
	Phase string
	// RequestsSent is the scan's requests so far, written to total_requests.
	// Nil leaves total_requests untouched, for a caller that does not count.
	RequestsSent *int64
	PID          int
	Host         string
}

// UpdateScanHeartbeat stamps a running scan's row with its latest beat: one
// small UPDATE, by uuid, touching only the liveness columns (and
// total_requests). updated_at is deliberately left alone — it is the row's
// edit time, and a heartbeat every few seconds would make it meaningless as
// one; heartbeat_at is the liveness column.
//
// Only a row still "running" is touched: a late beat must never re-stamp a
// finalized row. updated reports whether a row was written, which is how a
// heartbeat learns its scan was finalized by someone else.
func (r *Repository) UpdateScanHeartbeat(ctx context.Context, scanUUID string, hb ScanHeartbeat) (updated bool, err error) {
	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("heartbeat_at = ?", hb.At).
		Where("uuid = ?", scanUUID).
		Where("status = ?", "running")
	if hb.Phase == "" {
		q = q.Set("current_phase = NULL")
	} else {
		q = q.Set("current_phase = ?", hb.Phase)
	}
	if hb.PID > 0 {
		q = q.Set("pid = ?", hb.PID)
	}
	if hb.Host != "" {
		q = q.Set("runner_host = ?", hb.Host)
	}
	if hb.RequestsSent != nil {
		q = q.Set("total_requests = ?", *hb.RequestsSent)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LastScanLogTimes returns, per scan, the newest scan_logs.created_at — one
// GROUP BY over every listed scan, for liveness readers that list many scans at
// once. Scans with no log lines are absent from the map.
//
// projectUUIDs narrows the read to the projects the scans belong to, which is
// what lets the (project_uuid, scan_uuid) index serve it; pass none to read
// across projects (a stateless read of a standalone file).
func (r *Repository) LastScanLogTimes(ctx context.Context, projectUUIDs, scanUUIDs []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(scanUUIDs))
	if len(scanUUIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		ScanUUID string    `bun:"scan_uuid"`
		Last     time.Time `bun:"last_at"`
	}
	q := r.db.NewSelect().
		TableExpr("scan_logs").
		ColumnExpr("scan_uuid").
		ColumnExpr("MAX(created_at) AS last_at").
		Where("scan_uuid IN (?)", bun.List(scanUUIDs)).
		GroupExpr("scan_uuid")
	if len(projectUUIDs) > 0 {
		q = q.Where("project_uuid IN (?)", bun.List(projectUUIDs))
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !row.Last.IsZero() {
			out[row.ScanUUID] = row.Last
		}
	}
	return out, nil
}
