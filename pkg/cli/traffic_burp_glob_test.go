package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// writeGlobSQLiteFixture writes a standalone .sqlite result file holding n HTTP
// records for one host, each with a raw request/response so it is eligible for
// the Site map. Returns the file path.
func writeGlobSQLiteFixture(t *testing.T, dir, host string, n int) string {
	t.Helper()
	path := filepath.Join(dir, "scan-"+host+".sqlite")

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB(%s): %v", path, err)
	}
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	for i := range n {
		url := fmt.Sprintf("https://%s/p%d", host, i)
		_, err := db.NewInsert().Model(&database.HTTPRecord{
			UUID:        fmt.Sprintf("%s-rec-%d", host, i),
			ProjectUUID: "proj-" + host,
			Scheme:      "https",
			Hostname:    host,
			Port:        443,
			Method:      "GET",
			Path:        fmt.Sprintf("/p%d", i),
			URL:         url,
			HTTPVersion: "HTTP/1.1",
			RequestHash: fmt.Sprintf("%s-rh-%d", host, i),
			StatusCode:  200,
			HasResponse: true,
			RawRequest:  []byte("GET /p" + fmt.Sprint(i) + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
			RawResponse: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	return path
}

// fakeSiteMapBridge stands in for the Burp/Caido listener, recording the URL of
// every record pushed to the Site map endpoint.
func fakeSiteMapBridge(t *testing.T) (url string, saved *[]string) {
	t.Helper()
	var mu sync.Mutex
	urls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/burp-bridge/sitemap" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode sitemap payload: %v", err)
			return
		}
		mu.Lock()
		urls = append(urls, fmt.Sprint(payload["url"]))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"added": 1, "url": payload["url"]})
	}))
	t.Cleanup(server.Close)
	return server.URL, &urls
}

// The whole point of the streaming path: every matched file's records reach Burp
// without any of them being merged into a shared database first.
func TestSaveGlobToBurpStreamsEveryMatchedFile(t *testing.T) {
	dir := t.TempDir()
	writeGlobSQLiteFixture(t, dir, "a.example", 3)
	writeGlobSQLiteFixture(t, dir, "b.example", 2)
	writeGlobSQLiteFixture(t, dir, "c.example", 4)

	bridgeURL, saved := fakeSiteMapBridge(t)
	restore := trafficBurpBridgeURL
	trafficBurpBridgeURL = bridgeURL
	t.Cleanup(func() { trafficBurpBridgeURL = restore })

	err := saveGlobToBurp(context.Background(), filepath.Join(dir, "scan-*.sqlite"),
		database.QueryFilters{SortBy: "sent_at"})
	if err != nil {
		t.Fatalf("saveGlobToBurp: %v", err)
	}
	if len(*saved) != 9 {
		t.Fatalf("expected all 9 records across 3 files to reach Burp, got %d: %v", len(*saved), *saved)
	}
}

// Per-file SQL still applies: a filter must narrow each file's query rather than
// being left to a merged result set that no longer exists.
func TestSaveGlobToBurpAppliesFiltersPerFile(t *testing.T) {
	dir := t.TempDir()
	writeGlobSQLiteFixture(t, dir, "a.example", 3)
	writeGlobSQLiteFixture(t, dir, "b.example", 3)

	bridgeURL, saved := fakeSiteMapBridge(t)
	restore := trafficBurpBridgeURL
	trafficBurpBridgeURL = bridgeURL
	t.Cleanup(func() { trafficBurpBridgeURL = restore })

	err := saveGlobToBurp(context.Background(), filepath.Join(dir, "scan-*.sqlite"),
		database.QueryFilters{HostPattern: "b.example"})
	if err != nil {
		t.Fatalf("saveGlobToBurp: %v", err)
	}
	if len(*saved) != 3 {
		t.Fatalf("expected only b.example's 3 records, got %d: %v", len(*saved), *saved)
	}
	for _, u := range *saved {
		if got := u; got[:len("https://b.example")] != "https://b.example" {
			t.Fatalf("filter leaked a record from another host: %s", got)
		}
	}
}

// A glob may mix formats. A .jsonl export has no queryable form on disk, so it
// goes through the importer — and must still be sent.
func TestSaveGlobToBurpReadsMixedFormats(t *testing.T) {
	dir := t.TempDir()
	writeGlobSQLiteFixture(t, dir, "a.example", 2)
	writeGlobFixture(t, filepath.Join(dir, "scan-b.jsonl"), "b.example", "hash-b", "sqli-error")

	bridgeURL, saved := fakeSiteMapBridge(t)
	restore := trafficBurpBridgeURL
	trafficBurpBridgeURL = bridgeURL
	t.Cleanup(func() { trafficBurpBridgeURL = restore })

	// The JSONL fixture's record carries no raw request, so it is offered to the
	// bridge and rejected there rather than silently dropped — Added counts only
	// the sqlite pair, but the run must not fail over it.
	err := saveGlobToBurp(context.Background(), filepath.Join(dir, "scan-*"),
		database.QueryFilters{})
	if err != nil {
		t.Fatalf("saveGlobToBurp: %v", err)
	}
	if len(*saved) != 2 {
		t.Fatalf("expected the 2 sqlite records to reach Burp, got %d: %v", len(*saved), *saved)
	}
}

// An unreadable match is skipped with a warning, exactly as the merged path does,
// rather than aborting the whole copy.
func TestSaveGlobToBurpSkipsUnreadableMatch(t *testing.T) {
	dir := t.TempDir()
	writeGlobSQLiteFixture(t, dir, "a.example", 2)
	if err := os.WriteFile(filepath.Join(dir, "scan-junk.sqlite"), []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}

	bridgeURL, saved := fakeSiteMapBridge(t)
	restore := trafficBurpBridgeURL
	trafficBurpBridgeURL = bridgeURL
	t.Cleanup(func() { trafficBurpBridgeURL = restore })

	err := saveGlobToBurp(context.Background(), filepath.Join(dir, "scan-*.sqlite"),
		database.QueryFilters{})
	if err != nil {
		t.Fatalf("saveGlobToBurp: %v", err)
	}
	if len(*saved) != 2 {
		t.Fatalf("expected the readable file's 2 records, got %d", len(*saved))
	}
}

func TestSaveGlobToBurpErrorsWhenPatternMatchesNothing(t *testing.T) {
	restore := trafficBurpBridgeURL
	trafficBurpBridgeURL = "http://127.0.0.1:9009"
	t.Cleanup(func() { trafficBurpBridgeURL = restore })

	err := saveGlobToBurp(context.Background(),
		filepath.Join(t.TempDir(), "nope-*.sqlite"), database.QueryFilters{})
	if err == nil {
		t.Fatal("expected an error when the glob matches no files")
	}
}

// -n/--limit is a budget spent across files, not a per-file cap: without this the
// default 100-record limit would send 100 records from every matched file.
func TestGlobBurpSelectorSpendsLimitAcrossFiles(t *testing.T) {
	selector := newGlobBurpSelector(5, 0)

	first := selector.take(recordsWithUUIDs("a1", "a2", "a3"))
	if len(first) != 3 {
		t.Fatalf("first file: got %d records, want 3", len(first))
	}
	if selector.done() {
		t.Fatal("budget of 5 must survive a 3-record file")
	}
	second := selector.take(recordsWithUUIDs("b1", "b2", "b3", "b4"))
	if len(second) != 2 {
		t.Fatalf("second file: got %d records, want the 2 the budget still allowed", len(second))
	}
	if !selector.done() {
		t.Fatal("budget must be spent after 5 records")
	}
	if got := selector.fetchLimit(); got != 0 {
		t.Fatalf("a spent budget must not ask for more rows, got LIMIT %d", got)
	}
}

// --offset is burned in file order before anything is sent, and the per-file
// LIMIT has to cover it — asking for only the outstanding records would return a
// page consumed entirely by the skip.
func TestGlobBurpSelectorAppliesOffsetAcrossFiles(t *testing.T) {
	selector := newGlobBurpSelector(2, 3)
	if got := selector.fetchLimit(); got != 5 {
		t.Fatalf("fetchLimit = %d, want limit+offset = 5", got)
	}
	first := selector.take(recordsWithUUIDs("a1", "a2"))
	if len(first) != 0 {
		t.Fatalf("first 2 records must be consumed by the offset, got %d", len(first))
	}
	second := selector.take(recordsWithUUIDs("b1", "b2", "b3"))
	if len(second) != 2 {
		t.Fatalf("got %d records, want 2 after the offset is burned", len(second))
	}
	if second[0].UUID != "b2" || second[1].UUID != "b3" {
		t.Fatalf("offset landed wrong: %s, %s", second[0].UUID, second[1].UUID)
	}
}

// The merged path deduped on http_records' uuid primary key. Streaming has no
// shared table to collide in, so the selector has to carry that itself or a
// record present in two result files is pushed to Burp twice.
func TestGlobBurpSelectorDedupsByUUIDAcrossFiles(t *testing.T) {
	selector := newGlobBurpSelector(0, 0)
	if !selector.unlimited {
		t.Fatal("a zero limit means --all, i.e. unlimited")
	}
	first := selector.take(recordsWithUUIDs("shared", "a1"))
	second := selector.take(recordsWithUUIDs("shared", "b1"))
	if len(first) != 2 || len(second) != 1 {
		t.Fatalf("got %d then %d records, want 2 then 1 (the shared uuid deduped)", len(first), len(second))
	}
	if second[0].UUID != "b1" {
		t.Fatalf("wrong record survived dedup: %s", second[0].UUID)
	}
}

// An unlimited run must not put a LIMIT on any file's query.
func TestGlobBurpSelectorUnlimitedFetchesEverything(t *testing.T) {
	selector := newGlobBurpSelector(0, 0)
	if got := selector.fetchLimit(); got != 0 {
		t.Fatalf("fetchLimit = %d, want 0 (no LIMIT) under --all", got)
	}
	if selector.done() {
		t.Fatal("an unlimited selector is never done")
	}
}

// A plain SQLite match is queried in place; anything else is imported. Both must
// answer the same query interface.
func TestOpenGlobSourceFileHandlesBothForms(t *testing.T) {
	dir := t.TempDir()
	sqlitePath := writeGlobSQLiteFixture(t, dir, "a.example", 2)
	jsonlPath := filepath.Join(dir, "scan-b.jsonl")
	writeGlobFixture(t, jsonlPath, "b.example", "hash-b", "sqli-error")

	ctx := context.Background()
	for _, path := range []string{sqlitePath, jsonlPath} {
		db, closeDB, err := openGlobSourceFile(ctx, path)
		if err != nil {
			t.Fatalf("openGlobSourceFile(%s): %v", path, err)
		}
		var records []*database.HTTPRecord
		if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
			t.Fatalf("scan %s: %v", path, err)
		}
		if len(records) == 0 {
			t.Fatalf("%s produced no records", path)
		}
		closeDB()
	}
}

// Opening file N must not be answered by file 1 — the process-wide connection
// cache would do exactly that, which is why this path opens its own.
func TestOpenGlobSourceFileDoesNotShareOneCachedConnection(t *testing.T) {
	dir := t.TempDir()
	first := writeGlobSQLiteFixture(t, dir, "a.example", 1)
	second := writeGlobSQLiteFixture(t, dir, "b.example", 5)

	ctx := context.Background()
	counts := map[string]int{}
	for _, path := range []string{first, second} {
		db, closeDB, err := openGlobSourceFile(ctx, path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		var records []*database.HTTPRecord
		if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
			t.Fatalf("scan %s: %v", path, err)
		}
		counts[path] = len(records)
		closeDB()
	}
	if counts[first] != 1 || counts[second] != 5 {
		t.Fatalf("each file must answer for itself, got %d and %d", counts[first], counts[second])
	}
}

func TestGlobProgressIndexAlignsToTotalWidth(t *testing.T) {
	if got := globProgressIndex(12, 854); got != "[ 12/854]" {
		t.Fatalf("globProgressIndex = %q, want %q", got, "[ 12/854]")
	}
	if got := globProgressIndex(7, 9); got != "[7/9]" {
		t.Fatalf("globProgressIndex = %q, want %q", got, "[7/9]")
	}
}

func recordsWithUUIDs(uuids ...string) []*database.HTTPRecord {
	records := make([]*database.HTTPRecord, 0, len(uuids))
	for _, uuid := range uuids {
		records = append(records, &database.HTTPRecord{UUID: uuid})
	}
	return records
}
