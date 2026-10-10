package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type invRec struct {
	project, scan, scheme, host string
	port                        int
	method, path, source        string
	status                      int
	params                      []EmbeddedParam
	remarks                     []string
	auth                        string
}

func seedInventory(t *testing.T, db *DB, recs []invRec) {
	t.Helper()
	ctx := context.Background()
	for i, r := range recs {
		if r.project == "" {
			r.project = "proj-1"
		}
		if r.scheme == "" {
			r.scheme = "https"
		}
		if r.port == 0 {
			r.port = 443
		}
		if r.host == "" {
			r.host = "a.test"
		}
		if r.method == "" {
			r.method = "GET"
		}
		if r.status == 0 {
			r.status = 200
		}
		rec := &HTTPRecord{
			UUID:                 fmt.Sprintf("rec-%05d", i),
			ProjectUUID:          r.project,
			ScanUUID:             r.scan,
			Scheme:               r.scheme,
			Hostname:             r.host,
			Port:                 r.port,
			Method:               r.method,
			Path:                 r.path,
			URL:                  r.scheme + "://" + r.host + r.path,
			HTTPVersion:          "HTTP/1.1",
			RequestHash:          fmt.Sprintf("h%d", i),
			StatusCode:           r.status,
			HasResponse:          true,
			ResponseContentType:  "application/json; charset=utf-8",
			RawRequest:           []byte("GET " + r.path + " HTTP/1.1\r\nHost: " + r.host + "\r\n\r\n"),
			RawResponse:          []byte("HTTP/1.1 200 OK\r\n\r\n{}"),
			Parameters:           r.params,
			Source:               r.source,
			Remarks:              r.remarks,
			RequestAuthorization: r.auth,
			CreatedAt:            time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
			SentAt:               time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("seed record: %v", err)
		}
	}
}

func endpointByTemplate(t *testing.T, res EndpointResult, template string) EndpointView {
	t.Helper()
	for _, e := range res.Endpoints {
		if e.Template == template {
			return e
		}
	}
	var got []string
	for _, e := range res.Endpoints {
		got = append(got, e.Template)
	}
	t.Fatalf("no endpoint %q in %v", template, got)
	return EndpointView{}
}

func TestEndpointsGroupsByTemplate(t *testing.T) {
	db := newTestDB(t)
	var recs []invRec
	for i := 1; i <= 50; i++ {
		recs = append(recs, invRec{path: fmt.Sprintf("/users/%d", i)})
	}
	recs = append(recs,
		invRec{method: "POST", path: "/users/7", status: 201, auth: "Bearer x",
			params: []EmbeddedParam{{Name: "name", Value: "a", Type: "json"}}},
		invRec{path: "/users/me"},
		invRec{path: "/about?x=1", params: []EmbeddedParam{{Name: "x", Value: "1", Type: "url"}}},
		invRec{path: "/users/3", project: "proj-2"}, // other project: never counted
	)
	seedInventory(t, db, recs)

	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(context.Background(), EndpointOptions{})
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	if res.Total != 3 || res.RecordsScanned != 53 {
		t.Fatalf("total=%d scanned=%d, want 3 endpoints over 53 records", res.Total, res.RecordsScanned)
	}
	users := endpointByTemplate(t, res, "/users/{int}")
	if users.Records != 51 || users.DistinctPaths != 50 {
		t.Errorf("records=%d distinct_paths=%d, want 51/50", users.Records, users.DistinctPaths)
	}
	if strings.Join(users.Methods, ",") != "GET,POST" {
		t.Errorf("methods = %v", users.Methods)
	}
	if len(users.SamplePaths) != 3 {
		t.Errorf("sample_paths = %v, want 3", users.SamplePaths)
	}
	if users.Origin != "https://a.test" || users.ID != EndpointID("https://a.test", "/users/{int}") {
		t.Errorf("origin=%q id=%q", users.Origin, users.ID)
	}
	if users.Auth.Authenticated != 1 || users.Auth.Anonymous != 50 {
		t.Errorf("auth = %+v", users.Auth)
	}
	if users.Status["200"] != 50 || users.Status["201"] != 1 || users.TopStatus != 200 {
		t.Errorf("status = %v top=%d", users.Status, users.TopStatus)
	}
	if strings.Join(users.Params["json"], ",") != "name" || strings.Join(users.Params["path"], ",") != "{int}@1" {
		t.Errorf("params = %v", users.Params)
	}
	if strings.Join(users.ResponseContentTypes, ",") != "application/json" {
		t.Errorf("response content types = %v", users.ResponseContentTypes)
	}
	// Literal segments never collapse.
	endpointByTemplate(t, res, "/users/me")
	about := endpointByTemplate(t, res, "/about")
	if strings.Join(about.Params["query"], ",") != "x" {
		t.Errorf("about params = %v", about.Params)
	}
	// Default sort: most records first.
	if res.Endpoints[0].Template != "/users/{int}" {
		t.Errorf("first endpoint = %q, want the busiest", res.Endpoints[0].Template)
	}

	// Paging and min-records.
	page, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(context.Background(), EndpointOptions{MinRecords: 2, Sort: "template"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Endpoints[0].Template != "/users/{int}" {
		t.Errorf("min-records: total=%d", page.Total)
	}
}

func TestEndpointsFiltersAndProvenance(t *testing.T) {
	db := newTestDB(t)
	seedInventory(t, db, []invRec{
		{path: "/a", scan: "scan-1"},
		{path: "/b", scan: "scan-2"},
		{path: "/api/v1/orders", source: "jstangle", remarks: []string{"jstangle:not_found", "jstangle:src=https://a.test/app.js#L3"}},
	})
	ctx := context.Background()

	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1", ScanUUID: "scan-1"}).Endpoints(ctx, EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || res.Endpoints[0].Template != "/a" {
		t.Errorf("--scan-uuid must select the scan's own records, got %+v", res.Endpoints)
	}

	res, err = NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1", Source: "jstangle"}).Endpoints(ctx, EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 {
		t.Fatalf("--source jstangle: total=%d", res.Total)
	}
	js := res.Endpoints[0]
	if strings.Join(js.JSOutcomes, ",") != "not_found" || strings.Join(js.Sources, ",") != "jstangle" {
		t.Errorf("js_outcomes=%v sources=%v", js.JSOutcomes, js.Sources)
	}

	res, err = NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1", Remarks: []string{"jstangle:"}}).Endpoints(ctx, EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || res.Endpoints[0].Template != "/api/v1/orders" {
		t.Errorf("--remark jstangle: got %d endpoints", res.Total)
	}
}

func TestEndpointsFindingCounts(t *testing.T) {
	db := newTestDB(t)
	seedInventory(t, db, []invRec{{path: "/users/1"}, {path: "/users/2"}, {path: "/about"}})
	ctx := context.Background()
	repo := NewRepository(db)
	for i, f := range []struct{ url, sev, status, project string }{
		{"https://a.test/users/9?x=1", "high", "", "proj-1"},
		{"https://a.test:443/users/10", "low", "triaged", "proj-1"},
		{"https://a.test/users/11", "critical", "false_positive", "proj-1"}, // dismissed
		{"https://a.test/users/12", "critical", "", "proj-2"},               // other project
		{"https://other.test/users/1", "critical", "", "proj-1"},            // other origin
	} {
		if err := repo.SaveFindingDirect(ctx, &Finding{
			ProjectUUID: f.project, ModuleID: "m", ModuleName: "M", Severity: f.sev, Confidence: "firm",
			FindingHash: fmt.Sprintf("fh%d", i), URL: f.url, Hostname: "a.test", Status: f.status,
		}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(ctx, EndpointOptions{Sort: "findings"})
	if err != nil {
		t.Fatal(err)
	}
	users := endpointByTemplate(t, res, "/users/{int}")
	if users.Findings != 2 || users.MaxSeverity != "high" || users.FindingsBySeverity["low"] != 1 {
		t.Errorf("findings=%d max=%q by=%v", users.Findings, users.MaxSeverity, users.FindingsBySeverity)
	}
	if res.Endpoints[0].Template != "/users/{int}" {
		t.Errorf("--sort findings: first = %q", res.Endpoints[0].Template)
	}
}

func TestEndpointsCollapse(t *testing.T) {
	db := newTestDB(t)
	seedInventory(t, db, []invRec{
		{path: "/blog/first-post"}, {path: "/blog/second-post"}, {path: "/blog/third-post"},
		{path: "/blog/feed/rss"},
		{path: "/docs/a/edit"}, {path: "/docs/b/edit"}, {path: "/docs/c/edit"},
	})
	ctx := context.Background()

	off, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(ctx, EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if off.Total != 7 {
		t.Fatalf("collapse off: total=%d, want 7 (it is opt-in)", off.Total)
	}

	on, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(ctx, EndpointOptions{Collapse: 3})
	if err != nil {
		t.Fatal(err)
	}
	blog := endpointByTemplate(t, on, "/blog/{var}")
	if blog.Records != 3 || blog.DistinctPaths != 3 {
		t.Errorf("blog: records=%d distinct=%d", blog.Records, blog.DistinctPaths)
	}
	endpointByTemplate(t, on, "/blog/feed/rss") // different child set: untouched
	docs := endpointByTemplate(t, on, "/docs/{var}/edit")
	if docs.Records != 3 {
		t.Errorf("docs: records=%d", docs.Records)
	}
	if on.Total != 3 {
		t.Errorf("collapse 3: total=%d, want 3", on.Total)
	}
}

func TestEndpointsCap(t *testing.T) {
	db := newTestDB(t)
	seedInventory(t, db, []invRec{{path: "/a"}, {path: "/b"}, {path: "/c"}, {path: "/a"}})
	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(context.Background(), EndpointOptions{MaxEndpoints: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Capped || res.UnbucketedRecords != 1 || res.Total != 2 {
		t.Errorf("capped=%v unbucketed=%d total=%d", res.Capped, res.UnbucketedRecords, res.Total)
	}
}

// The stream reads light columns only: the raw corpus dwarfs everything else
// and an inventory never renders it.
func TestInventoryQuerySkipsRawColumns(t *testing.T) {
	db := newTestDB(t)
	q := NewQueryBuilder(db, QueryFilters{ProjectUUID: "p", HostPattern: "a.test"}).inventoryPageQuery("rec-1", 10).String()
	for _, col := range []string{"raw_request", "raw_response", `"r".*`, "r.*"} {
		if strings.Contains(q, col) {
			t.Errorf("inventory query selects %s: %s", col, q)
		}
	}
	if !strings.Contains(q, "r.uuid > 'rec-1'") || !strings.Contains(q, "ORDER BY r.uuid ASC") {
		t.Errorf("inventory query is not uuid-keyset paged: %s", q)
	}
}

func TestEndpointsPagesThroughTheStream(t *testing.T) {
	db := newTestDB(t)
	var recs []invRec
	for i := 0; i < inventoryPageSize+5; i++ {
		recs = append(recs, invRec{path: fmt.Sprintf("/items/%d", i)})
	}
	seedInventory(t, db, recs)
	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "proj-1"}).Endpoints(context.Background(), EndpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecordsScanned != int64(len(recs)) || res.Endpoints[0].Records != int64(len(recs)) {
		t.Errorf("scanned=%d records=%d, want %d", res.RecordsScanned, res.Endpoints[0].Records, len(recs))
	}
	if !res.Endpoints[0].PathsCapped || res.Endpoints[0].DistinctPaths != endpointDistinctPathCap {
		t.Errorf("distinct paths = %d capped=%v", res.Endpoints[0].DistinctPaths, res.Endpoints[0].PathsCapped)
	}
}
