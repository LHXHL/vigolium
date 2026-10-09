package database

import (
	"time"

	"github.com/uptrace/bun"
)

// Scan-row names and modes for single-request scans: the scan-url / scan-request
// direct path in the CLI and the REST /api/scan-url and /api/scan-request
// handlers. One spelling each, so `db ls --table scans` groups them the same
// way whichever surface started the scan.
const (
	ScanNameScanURL     = "scan-url"
	ScanNameScanRequest = "scan-request"
	ScanModeSingle      = "single"
)

// NewSingleRequestScan builds the scan row for a single-request scan.
//
// It is the one constructor for that row. The REST handlers used to build it
// inline, twice, and the CLI direct path created no row at all, so a finding
// carried a scan_uuid nothing could look up. name is ScanNameScanURL or
// ScanNameScanRequest; source is the ScanSource label ("cli" or "api").
// The row starts "running" with StartedAt now; CompleteScanWithOutcome closes it.
func NewSingleRequestScan(uuid, projectUUID, name, target, modules, source string) *Scan {
	return &Scan{
		UUID:        uuid,
		ProjectUUID: projectUUID,
		Name:        name,
		Status:      "running",
		Target:      target,
		Modules:     modules,
		ScanSource:  source,
		ScanMode:    ScanModeSingle,
		StartedAt:   time.Now(),
	}
}

// WhereScanRecords narrows an http_records query (alias "r") to the exchanges
// one scan accounts for: the rows it stored first (http_records.scan_uuid) plus
// any row one of its findings cites as evidence. The second half matters
// because records are deduplicated across scans: a rescan's finding can point
// at an exchange an earlier scan stored, and a scan-scoped export that dropped
// it would ship the finding without its proof.
//
// CountRecordsForScan deliberately counts only the first half — it answers
// "how many records did this scan write".
func WhereScanRecords(q *bun.SelectQuery, scanUUID string) *bun.SelectQuery {
	return q.Where("(r.scan_uuid = ? OR r.uuid IN (SELECT fr.record_uuid FROM finding_records AS fr "+
		"JOIN findings AS sf ON sf.id = fr.finding_id WHERE sf.scan_uuid = ?))", scanUUID, scanUUID)
}
