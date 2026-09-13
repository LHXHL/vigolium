package database

import (
	"context"
	"fmt"
	"testing"
)

// TestAppendRecordsToFindingCapsEvidence guards the one evidence-merge site that
// skipped maxAdditionalEvidence. A finding re-detected across many URLs appended
// one full request/response pair per re-detection, so a single row grew without
// bound — the other three merge sites (converters, dedup x2) already capped.
func TestAppendRecordsToFindingCapsEvidence(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	base := &Finding{
		ProjectUUID: DefaultProjectUUID,
		ModuleID:    "hdr",
		ModuleName:  "Missing header",
		Severity:    "low",
		Confidence:  "firm",
		FindingHash: "same-hash",
		URL:         "https://a.example/0",
		Hostname:    "a.example",
		Request:     "GET /0 HTTP/1.1\r\nHost: a.example\r\n\r\n",
		Response:    "HTTP/1.1 200 OK\r\n\r\nzero",
	}
	if err := repo.SaveFindingDirect(ctx, base); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Re-detect the same finding many times over, each with distinct evidence.
	const redetections = 40
	for i := 1; i <= redetections; i++ {
		dup := *base
		dup.ID = 0
		dup.URL = fmt.Sprintf("https://a.example/%d", i)
		dup.Request = fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: a.example\r\n\r\n", i)
		dup.Response = fmt.Sprintf("HTTP/1.1 200 OK\r\n\r\nbody-%d", i)
		if err := repo.SaveFindingDirect(ctx, &dup); err != nil {
			t.Fatalf("re-detection %d: %v", i, err)
		}
	}

	survivor := &Finding{}
	if err := db.NewSelect().Model(survivor).
		Where("project_uuid = ?", DefaultProjectUUID).
		Where("finding_hash = ?", "same-hash").Scan(ctx); err != nil {
		t.Fatalf("load survivor: %v", err)
	}

	if got := len(survivor.AdditionalEvidence); got > maxAdditionalEvidence {
		t.Errorf("additional evidence = %d entries after %d re-detections, want <= %d",
			got, redetections, maxAdditionalEvidence)
	}
	// The primary evidence must survive the capping untouched.
	if survivor.Response != "HTTP/1.1 200 OK\r\n\r\nzero" {
		t.Errorf("primary response was disturbed: %q", survivor.Response)
	}
}
