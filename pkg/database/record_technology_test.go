package database

import (
	"context"
	"fmt"
	"testing"
)

// seedTechRecords inserts n bare http_records and returns their UUIDs.
func seedTechRecords(t *testing.T, db *DB, n int) []string {
	t.Helper()
	ctx := context.Background()
	uuids := make([]string, 0, n)
	for i := range n {
		uuid := fmt.Sprintf("rec-%d", i)
		rec := &HTTPRecord{
			UUID:     uuid,
			URL:      fmt.Sprintf("https://example.com/%d", i),
			Hostname: "example.com",
			Method:   "GET",
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("seed record %d: %v", i, err)
		}
		uuids = append(uuids, uuid)
	}
	return uuids
}

// readTechnology reads back the technology column for one record.
func readTechnology(t *testing.T, db *DB, uuid string) []string {
	t.Helper()
	var rec HTTPRecord
	if err := db.NewSelect().Model(&rec).Where("uuid = ?", uuid).Scan(context.Background()); err != nil {
		t.Fatalf("read record %s: %v", uuid, err)
	}
	return rec.Technology
}

func TestSetRecordTechnology(t *testing.T) {
	db := newTestDB(t)
	uuids := seedTechRecords(t, db, 3)

	err := NewRepository(db).SetRecordTechnology(context.Background(), map[string][]string{
		uuids[0]: {"django", "nginx"},
		uuids[1]: {"django", "nginx"},
		uuids[2]: {"spring"},
	})
	if err != nil {
		t.Fatalf("SetRecordTechnology: %v", err)
	}

	for _, tc := range []struct {
		uuid string
		want []string
	}{
		{uuids[0], []string{"django", "nginx"}},
		{uuids[1], []string{"django", "nginx"}},
		{uuids[2], []string{"spring"}},
	} {
		got := readTechnology(t, db, tc.uuid)
		if len(got) != len(tc.want) {
			t.Fatalf("%s technology = %v, want %v", tc.uuid, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%s technology = %v, want %v", tc.uuid, got, tc.want)
			}
		}
	}
}

// TestSetRecordTechnologyReplaces pins the replace-not-merge contract. The
// column holds the fingerprint modules' current verdict, recomputed every scan;
// merging would make a record carry a stack the target stopped running.
func TestSetRecordTechnologyReplaces(t *testing.T) {
	db := newTestDB(t)
	uuids := seedTechRecords(t, db, 1)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.SetRecordTechnology(ctx, map[string][]string{uuids[0]: {"django", "nginx"}}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := repo.SetRecordTechnology(ctx, map[string][]string{uuids[0]: {"spring"}}); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got := readTechnology(t, db, uuids[0])
	if len(got) != 1 || got[0] != "spring" {
		t.Errorf("technology = %v, want [spring] - the second write must replace, not merge", got)
	}
}

// TestSetRecordTechnologySkipsEmpty verifies an empty list is not written. A
// host no fingerprint module recognised must read as "not fingerprinted", which
// a NULL column says and an empty array does not.
func TestSetRecordTechnologySkipsEmpty(t *testing.T) {
	db := newTestDB(t)
	uuids := seedTechRecords(t, db, 1)
	ctx := context.Background()
	repo := NewRepository(db)

	if err := repo.SetRecordTechnology(ctx, map[string][]string{uuids[0]: {"django"}}); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := repo.SetRecordTechnology(ctx, map[string][]string{uuids[0]: {}, "": {"x"}}); err != nil {
		t.Fatalf("empty write: %v", err)
	}

	got := readTechnology(t, db, uuids[0])
	if len(got) != 1 || got[0] != "django" {
		t.Errorf("technology = %v, want [django] left untouched by an empty write", got)
	}
}

// TestSetRecordTechnologyBatchesAcrossGroups exercises the grouping path with
// more records than the 500-row chunk so the IN() clause is split.
func TestSetRecordTechnologyBatchesAcrossGroups(t *testing.T) {
	db := newTestDB(t)
	uuids := seedTechRecords(t, db, 1100)

	technology := make(map[string][]string, len(uuids))
	for i, uuid := range uuids {
		if i%2 == 0 {
			technology[uuid] = []string{"django"}
		} else {
			technology[uuid] = []string{"spring"}
		}
	}
	if err := NewRepository(db).SetRecordTechnology(context.Background(), technology); err != nil {
		t.Fatalf("SetRecordTechnology: %v", err)
	}

	for _, i := range []int{0, 1, 999, 1099} {
		want := "django"
		if i%2 == 1 {
			want = "spring"
		}
		got := readTechnology(t, db, uuids[i])
		if len(got) != 1 || got[0] != want {
			t.Errorf("record %d technology = %v, want [%s]", i, got, want)
		}
	}
}
