package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// makeTestPost builds a POST request/response with a body so the resulting
// record carries a non-zero request_hash / content length.
func makeTestPost(t *testing.T, path, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n%s",
		path, len(body), body)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest(%q): %v", path, err)
	}
	return rr
}

func toRecord(t *testing.T, rr *httpmsg.HttpRequestResponse, source string) *HTTPRecord {
	t.Helper()
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}
	rec.Source = source
	rec.ProjectUUID = defaultProjectUUID("")
	return rec
}

func countRecords(t *testing.T, db *DB) int {
	t.Helper()
	n, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestRecordWriter_DedupAgainstPreexisting verifies the flush-time batched dedup
// returns the existing UUID for a record already in the database and does not
// insert a second row.
func TestRecordWriter_DedupAgainstPreexisting(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Seed a record directly.
	seedUUID, err := repo.SaveRecord(ctx, makeTestRequest(7), "seed", "")
	if err != nil {
		t.Fatalf("seed SaveRecord: %v", err)
	}

	writer := NewRecordWriter(repo, RecordWriterConfig{
		BatchSize: 100,
		Shards:    1,
	})

	// Write the same request (distinct object, identical bytes) through the writer.
	gotUUID, err := writer.Write(ctx, makeTestRequest(7), "batched", "")
	if err != nil {
		t.Fatalf("writer.Write: %v", err)
	}
	writer.Close()

	if gotUUID != seedUUID {
		t.Errorf("dedup returned %q, want pre-existing %q", gotUUID, seedUUID)
	}
	if n := countRecords(t, db); n != 1 {
		t.Errorf("expected 1 record after dedup, got %d", n)
	}
}

// TestRecordWriter_WithinBatchDedup verifies that two identical new records in
// one flush batch collapse to a single insert and share one UUID, rather than
// racing to insert two rows.
//
// flush() is driven directly rather than through two concurrent Write() calls.
// That older shape depended on both writes landing inside one flush-timer
// window, and the flush loop no longer waits out a timer before committing — so
// the two records would usually reach the database in separate batches and be
// deduplicated by the SQL lookup instead. The assertions still passed, which is
// the problem: the test would have gone on reporting that within-batch
// collapsing worked without ever exercising it.
func TestRecordWriter_WithinBatchDedup(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	writer := NewRecordWriter(repo, RecordWriterConfig{
		Shards:         1,
		DedupCacheSize: -1, // disable the cache so nothing resolves before the batch
	})
	defer writer.Close()

	results := make([]chan WriteResult, 2)
	batch := make([]writeRequest, 0, 2)
	for i := range results {
		record := &HTTPRecord{}
		if err := record.PrepareIdentity(makeTestRequest(42)); err != nil {
			t.Fatalf("PrepareIdentity: %v", err)
		}
		record.Source = "dup"
		record.ProjectUUID = defaultProjectUUID("")
		if err := record.EnrichFromHttpRequestResponse(makeTestRequest(42)); err != nil {
			t.Fatalf("EnrichFromHttpRequestResponse: %v", err)
		}
		results[i] = make(chan WriteResult, 1)
		batch = append(batch, writeRequest{
			record:   record,
			result:   results[i],
			dedupKey: recordDedupKey(record),
		})
	}

	writer.flush(ctx, batch)

	uuids := make([]string, len(results))
	for i, ch := range results {
		select {
		case res := <-ch:
			if res.Err != nil {
				t.Fatalf("write %d: %v", i, res.Err)
			}
			uuids[i] = res.UUID
		default:
			t.Fatalf("write %d never received a result", i)
		}
	}

	if uuids[0] != uuids[1] {
		t.Errorf("within-batch duplicates got distinct UUIDs %q vs %q", uuids[0], uuids[1])
	}
	if n := countRecords(t, db); n != 1 {
		t.Errorf("expected 1 row for within-batch duplicates, got %d", n)
	}
}

// TestFindDuplicateRecordUUIDs covers the batched lookup directly, including the
// request_hash differentiation for records that carry a body.
func TestFindDuplicateRecordUUIDs(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	getUUID, err := repo.SaveRecord(ctx, makeTestRequest(1), "seed", "")
	if err != nil {
		t.Fatalf("seed GET: %v", err)
	}
	postUUID, err := repo.SaveRecord(ctx, makeTestPost(t, "/api", "hello"), "seed", "")
	if err != nil {
		t.Fatalf("seed POST: %v", err)
	}

	// Sanity: the seeded POST must carry a body so request_hash matters.
	bodyRec := toRecord(t, makeTestPost(t, "/api", "hello"), "probe")
	if bodyRec.RequestContentLength == 0 || bodyRec.RequestHash == "" {
		t.Fatalf("expected POST record to have a body hash, got len=%d hash=%q",
			bodyRec.RequestContentLength, bodyRec.RequestHash)
	}

	lookup := []*HTTPRecord{
		toRecord(t, makeTestRequest(1), "probe"), // matches seeded GET
		bodyRec,                                  // matches seeded POST (same body)
		toRecord(t, makeTestPost(t, "/api", "world"), ""), // same endpoint, different body -> no match
		toRecord(t, makeTestRequest(999), "probe"),        // brand new -> no match
	}

	got, err := repo.findDuplicateRecordUUIDs(ctx, lookup)
	if err != nil {
		t.Fatalf("findDuplicateRecordUUIDs: %v", err)
	}
	if len(got) != len(lookup) {
		t.Fatalf("expected %d results, got %d", len(lookup), len(got))
	}
	if got[0] != getUUID {
		t.Errorf("GET dup: got %q, want %q", got[0], getUUID)
	}
	if got[1] != postUUID {
		t.Errorf("POST dup (same body): got %q, want %q", got[1], postUUID)
	}
	if got[2] != "" {
		t.Errorf("POST different body should not match, got %q", got[2])
	}
	if got[3] != "" {
		t.Errorf("brand-new record should not match, got %q", got[3])
	}
}

// makeTestGet builds a no-body GET request with an optional extra header line
// (e.g. "Origin: https://attacker.example"). method/host/path/url stay fixed, so
// only the raw request bytes — and thus request_hash — change with the header.
func makeTestGet(t *testing.T, path, headerLine string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := "GET " + path + " HTTP/1.1\r\nHost: example.com\r\n"
	if headerLine != "" {
		raw += headerLine + "\r\n"
	}
	raw += "\r\n"
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest(%q): %v", path, err)
	}
	return rr
}

// TestFindDuplicateRecordUUIDs_ExactIdentityForFindingSource is the Claim-1
// regression: a no-body, header-only mutation (e.g. an Origin probe) that leaves
// method/host/path/url unchanged must NOT collapse onto the baseline record when
// its source is finding-evidence (finding/candidate/observation), but the coarse
// no-body dedup is preserved for crawler/ingest sources.
func TestFindDuplicateRecordUUIDs_ExactIdentityForFindingSource(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Baseline crawler record, no Origin header.
	baselineUUID, err := repo.SaveRecord(ctx, makeTestGet(t, "/exact", ""), "scanner", "")
	if err != nil {
		t.Fatalf("seed baseline: %v", err)
	}

	findingProbe := toRecord(t, makeTestGet(t, "/exact", "Origin: https://attacker.example"), RecordKindFinding)
	crawlerProbe := toRecord(t, makeTestGet(t, "/exact", "Origin: https://attacker.example"), "scanner")
	findingSame := toRecord(t, makeTestGet(t, "/exact", ""), RecordKindFinding)

	// Sanity: the header-mutated probe is a no-body request whose request_hash
	// differs from the baseline (otherwise the test proves nothing).
	if findingProbe.RequestContentLength != 0 {
		t.Fatalf("expected no-body probe, got content length %d", findingProbe.RequestContentLength)
	}

	got, err := repo.findDuplicateRecordUUIDs(ctx, []*HTTPRecord{findingProbe, crawlerProbe, findingSame})
	if err != nil {
		t.Fatalf("findDuplicateRecordUUIDs: %v", err)
	}
	if got[0] != "" {
		t.Errorf("finding-source header-mutated probe must not collapse onto baseline, got %q", got[0])
	}
	if got[1] != baselineUUID {
		t.Errorf("crawler-source no-body probe should keep coarse dedup onto baseline, got %q want %q", got[1], baselineUUID)
	}
	if got[2] != baselineUUID {
		t.Errorf("finding-source probe with identical bytes should link to the same exchange, got %q want %q", got[2], baselineUUID)
	}
}

// TestAdoptRecordSourcePromotesFindingEvidence is the regression for the label
// that made `vigolium traffic --source probe` hide the sweep's own pages.
//
// A passive module persists the response it reports on BEFORE the item's own
// save runs, so the finding-evidence row wins the dedup and the phase's row —
// and its source — is discarded. Every terminal response a passive module
// touched then reads as "finding", which on a host sweep is every page fetched.
func TestAdoptRecordSourcePromotesFindingEvidence(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	sourceOf := func(uuid string) string {
		var got string
		if err := db.NewSelect().Model((*HTTPRecord)(nil)).
			Column("source").Where("uuid = ?", uuid).Scan(ctx, &got); err != nil {
			t.Fatalf("read source: %v", err)
		}
		return got
	}

	// A module got there first: the row exists as finding evidence.
	uuid, err := repo.SaveRecord(ctx, makeTestGet(t, "/page", ""), RecordKindFinding, "")
	if err != nil {
		t.Fatalf("seed finding-evidence record: %v", err)
	}
	if got := sourceOf(uuid); got != RecordKindFinding {
		t.Fatalf("seed source = %q, want %q", got, RecordKindFinding)
	}

	// The probe phase's own save deduplicates onto it and must promote it.
	same, err := repo.SaveRecord(ctx, makeTestGet(t, "/page", ""), RecordSourceProbe, "")
	if err != nil {
		t.Fatalf("probe save: %v", err)
	}
	if same != uuid {
		t.Fatalf("expected dedup onto %s, got %s", uuid, same)
	}
	if got := sourceOf(uuid); got != RecordSourceProbe {
		t.Errorf("source = %q, want %q — the sweep's own page is still hidden from --source probe", got, RecordSourceProbe)
	}

	// Promote-only: a later crawl source must NOT relabel it, or "which phase
	// found this" degrades into "which phase saw it last".
	if _, err := repo.SaveRecord(ctx, makeTestGet(t, "/page", ""), "scanner", ""); err != nil {
		t.Fatalf("second crawl save: %v", err)
	}
	if got := sourceOf(uuid); got != RecordSourceProbe {
		t.Errorf("source = %q after a second crawl source, want it pinned at %q", got, RecordSourceProbe)
	}

	// Nor does finding evidence displace a crawl source in the other direction.
	if _, err := repo.SaveRecord(ctx, makeTestGet(t, "/page", ""), RecordKindFinding, ""); err != nil {
		t.Fatalf("late finding-evidence save: %v", err)
	}
	if got := sourceOf(uuid); got != RecordSourceProbe {
		t.Errorf("source = %q after late finding evidence, want %q", got, RecordSourceProbe)
	}
}
