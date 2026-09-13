package database

import (
	"context"
	"strings"
	"testing"
)

// seedGroupRecords inserts records with the given (host, method, status) shape.
func seedGroupRecords(t *testing.T, db *DB, specs []struct {
	host   string
	method string
	status int
	n      int
}) {
	t.Helper()
	ctx := context.Background()
	seq := 0
	for _, s := range specs {
		for i := 0; i < s.n; i++ {
			seq++
			rec := &HTTPRecord{
				UUID:        strings.ToLower(s.host) + "-" + s.method + "-" + itoa(seq),
				ProjectUUID: "proj-1",
				Scheme:      "https",
				Hostname:    s.host,
				Port:        443,
				Method:      s.method,
				Path:        "/p" + itoa(seq),
				URL:         "https://" + s.host + "/p" + itoa(seq),
				HTTPVersion: "HTTP/1.1",
				RequestHash: "h" + itoa(seq),
				StatusCode:  s.status,
				HasResponse: true,
				RawRequest:  []byte("GET / HTTP/1.1\r\n\r\n"),
			}
			if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
				t.Fatalf("seed record: %v", err)
			}
		}
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

func TestGroupRecordsByCountsUnderTheSameFilters(t *testing.T) {
	db := newTestDB(t)
	seedGroupRecords(t, db, []struct {
		host   string
		method string
		status int
		n      int
	}{
		{"alpha.example", "GET", 200, 5},
		{"alpha.example", "POST", 200, 2},
		{"bravo.example", "GET", 404, 3},
	})

	// The point of routing through applyFilters: a grouping describes exactly the
	// rows the same filters would have listed, not the whole table.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1", HostPattern: "alpha.example"})
	got, err := qb.GroupRecordsBy(context.Background(), "method", 10)
	if err != nil {
		t.Fatalf("GroupRecordsBy: %v", err)
	}
	if got.TotalRecords != 7 {
		t.Errorf("total_records = %d, want 7 (the host filter must apply)", got.TotalRecords)
	}
	if got.DistinctGroups != 2 {
		t.Errorf("distinct_groups = %d, want 2", got.DistinctGroups)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(got.Groups))
	}
	// Largest bucket first, so a capped list keeps the part that matters.
	if got.Groups[0].Value != "GET" || got.Groups[0].Count != 5 {
		t.Errorf("first group = %+v, want GET×5", got.Groups[0])
	}
	if got.OtherGroups != 0 || got.OtherRecords != 0 {
		t.Errorf("complete grouping must report no tail, got %+v", got)
	}
}

// A cap that reported only what fit would describe a partial result with a
// complete-looking number. The tail is counted instead.
func TestGroupRecordsByReportsTheTail(t *testing.T) {
	db := newTestDB(t)
	specs := []struct {
		host   string
		method string
		status int
		n      int
	}{
		{"a.example", "GET", 200, 4},
		{"b.example", "GET", 200, 3},
		{"c.example", "GET", 200, 2},
		{"d.example", "GET", 200, 1},
	}
	seedGroupRecords(t, db, specs)

	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"})
	got, err := qb.GroupRecordsBy(context.Background(), "host", 2)
	if err != nil {
		t.Fatalf("GroupRecordsBy: %v", err)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups = %d, want the 2 requested", len(got.Groups))
	}
	if got.DistinctGroups != 4 {
		t.Errorf("distinct_groups = %d, want 4 (the unbounded count)", got.DistinctGroups)
	}
	if got.TotalRecords != 10 {
		t.Errorf("total_records = %d, want 10 (the unbounded count)", got.TotalRecords)
	}
	if got.OtherGroups != 2 {
		t.Errorf("other_groups = %d, want 2", got.OtherGroups)
	}
	if got.OtherRecords != 3 {
		t.Errorf("other_records = %d, want 3 (c=2 + d=1)", got.OtherRecords)
	}
}

// status_code is an integer column; the group key has to survive as a comparable
// string on both drivers.
func TestGroupRecordsByNumericColumn(t *testing.T) {
	db := newTestDB(t)
	seedGroupRecords(t, db, []struct {
		host   string
		method string
		status int
		n      int
	}{
		{"a.example", "GET", 200, 3},
		{"a.example", "GET", 500, 1},
	})

	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"})
	got, err := qb.GroupRecordsBy(context.Background(), "status_code", 0)
	if err != nil {
		t.Fatalf("GroupRecordsBy: %v", err)
	}
	byValue := map[string]int64{}
	for _, g := range got.Groups {
		byValue[g.Value] = g.Count
	}
	if byValue["200"] != 3 || byValue["500"] != 1 {
		t.Errorf("groups = %+v, want 200×3 and 500×1", got.Groups)
	}
}

// The field name is a public name, not a physical column: accepting the storage
// spelling would make the schema part of the contract, and accepting anything at
// all would put a caller-supplied identifier into SQL.
func TestGroupRecordsByRejectsUnknownField(t *testing.T) {
	db := newTestDB(t)
	qb := NewQueryBuilder(db, QueryFilters{})

	for _, field := range []string{"hostname", "raw_response", "", "url; DROP TABLE http_records"} {
		_, err := qb.GroupRecordsBy(context.Background(), field, 10)
		if err == nil {
			t.Errorf("GroupRecordsBy(%q) must be rejected", field)
			continue
		}
		if !strings.Contains(err.Error(), "supported fields:") {
			t.Errorf("GroupRecordsBy(%q) must list the accepted names, got: %v", field, err)
		}
	}

	// And the public name for the hostname column is the one the record view uses.
	if _, err := GroupRecordsByField("host"); err != nil {
		t.Errorf("GroupRecordsByField(\"host\") = %v, want the hostname column", err)
	}
}

func TestGroupRecordsByEmptyStore(t *testing.T) {
	db := newTestDB(t)
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"})
	got, err := qb.GroupRecordsBy(context.Background(), "method", 10)
	if err != nil {
		t.Fatalf("GroupRecordsBy on an empty store must not error: %v", err)
	}
	if len(got.Groups) != 0 || got.TotalRecords != 0 || got.DistinctGroups != 0 {
		t.Errorf("empty store = %+v, want a zeroed grouping", got)
	}
}
