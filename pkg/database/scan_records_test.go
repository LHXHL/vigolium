package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNewSingleRequestScanDefaults(t *testing.T) {
	before := time.Now()
	s := NewSingleRequestScan("u-1", "p-1", ScanNameScanRequest, "http://a.example/x", "xss,sqli", "api")

	assert.Equal(t, "u-1", s.UUID)
	assert.Equal(t, "p-1", s.ProjectUUID)
	assert.Equal(t, "scan-request", s.Name)
	assert.Equal(t, "running", s.Status)
	assert.Equal(t, "http://a.example/x", s.Target)
	assert.Equal(t, "xss,sqli", s.Modules)
	assert.Equal(t, "api", s.ScanSource)
	assert.Equal(t, "single", s.ScanMode)
	assert.False(t, s.StartedAt.Before(before), "StartedAt is now")
	assert.Empty(t, s.Completeness, "a fresh row has no verdict yet")
}

func recordScanUUID(t *testing.T, db *DB, uuid string) string {
	t.Helper()
	var got string
	require.NoError(t, db.NewSelect().Model((*HTTPRecord)(nil)).Column("scan_uuid").
		Where("uuid = ?", uuid).Scan(context.Background(), &got))
	return got
}

// The writer stamps its scan on the rows it INSERTS and never on a dedup hit:
// http_records.scan_uuid is "the first scan to store this exchange", so a later
// scan that re-fetches it must not steal it — and records_written
// (CountRecordsForScan) counts exactly what each scan wrote.
func TestRecordWriterStampsScanUUIDOnInsertOnly(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	first := NewRecordWriter(repo, RecordWriterConfig{ScanUUID: "scan-1"})
	u1, err := first.Write(ctx, makeTestRequest(1), "test", DefaultProjectUUID)
	require.NoError(t, err)
	first.Close()

	// A second scan sees the same exchange (dedup hit, through a fresh writer so
	// the batched lookup path runs, not only the cache) and a new one.
	second := NewRecordWriter(repo, RecordWriterConfig{ScanUUID: "scan-2"})
	again, err := second.Write(ctx, makeTestRequest(1), "test", DefaultProjectUUID)
	require.NoError(t, err)
	u2, err := second.Write(ctx, makeTestRequest(2), "test", DefaultProjectUUID)
	require.NoError(t, err)
	// And a cache hit inside the same writer.
	cached, err := second.Write(ctx, makeTestRequest(2), "test", DefaultProjectUUID)
	require.NoError(t, err)
	second.Close()

	assert.Equal(t, u1, again, "the second scan dedups onto the first row")
	assert.Equal(t, u2, cached)
	assert.Equal(t, "scan-1", recordScanUUID(t, db, u1), "a dedup hit must not restamp the row")
	assert.Equal(t, "scan-2", recordScanUUID(t, db, u2))

	n1, err := repo.CountRecordsForScan(ctx, DefaultProjectUUID, "scan-1")
	require.NoError(t, err)
	n2, err := repo.CountRecordsForScan(ctx, DefaultProjectUUID, "scan-2")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n1, "records_written for scan-1")
	assert.Equal(t, int64(1), n2, "records_written for scan-2 excludes the deduped exchange")
}

// A write's own lineage outranks the writer default, and the unbatched
// repository path stamps from lineage too.
func TestRecordLineageScanUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	w := NewRecordWriter(repo, RecordWriterConfig{ScanUUID: "writer-scan"})
	u, err := w.WriteWithLineage(ctx, makeTestRequest(1), "test", DefaultProjectUUID, RecordLineage{ScanUUID: "lineage-scan"})
	require.NoError(t, err)
	w.Close()
	assert.Equal(t, "lineage-scan", recordScanUUID(t, db, u))

	direct, err := repo.SaveRecordWithLineage(ctx, makeTestRequest(2), "test", DefaultProjectUUID, RecordLineage{ScanUUID: "direct-scan"})
	require.NoError(t, err)
	assert.Equal(t, "direct-scan", recordScanUUID(t, db, direct))

	dup, err := repo.SaveRecordWithLineage(ctx, makeTestRequest(2), "test", DefaultProjectUUID, RecordLineage{ScanUUID: "later-scan"})
	require.NoError(t, err)
	assert.Equal(t, direct, dup)
	assert.Equal(t, "direct-scan", recordScanUUID(t, db, direct), "dedup hit keeps the first scan")

	plain, err := repo.SaveRecord(ctx, makeTestRequest(3), "test", DefaultProjectUUID)
	require.NoError(t, err)
	assert.Empty(t, recordScanUUID(t, db, plain), "no scan, no stamp")
}

// WhereScanRecords is the scan-scoped export's record set: what the scan stored
// plus the evidence its findings cite, even when an earlier scan stored that
// evidence first.
func TestWhereScanRecordsIncludesCitedEvidence(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	lin := func(scan string) RecordLineage { return RecordLineage{ScanUUID: scan} }
	old, err := repo.SaveRecordWithLineage(ctx, makeTestRequest(1), "test", DefaultProjectUUID, lin("scan-old"))
	require.NoError(t, err)
	mine, err := repo.SaveRecordWithLineage(ctx, makeTestRequest(2), "test", DefaultProjectUUID, lin("scan-new"))
	require.NoError(t, err)
	_, err = repo.SaveRecordWithLineage(ctx, makeTestRequest(3), "test", DefaultProjectUUID, lin("scan-old"))
	require.NoError(t, err)

	// scan-new's finding cites the exchange scan-old stored.
	ev := &output.ResultEvent{ModuleID: "m", URL: "http://example.com/path/1", Matched: "http://example.com/path/1"}
	ev.Info.Name = "n"
	ev.Info.Severity = severity.Low
	require.NoError(t, repo.SaveFinding(ctx, ev, []string{old}, "scan-new", DefaultProjectUUID))

	var uuids []string
	q := WhereScanRecords(db.NewSelect().Model((*HTTPRecord)(nil)).Column("r.uuid"), "scan-new")
	require.NoError(t, q.Scan(ctx, &uuids))
	assert.ElementsMatch(t, []string{old, mine}, uuids)
}
