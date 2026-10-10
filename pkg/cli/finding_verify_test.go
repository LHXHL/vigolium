package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// seedVerifyStore writes a store holding one scanned record against srvURL
// and one sqli-error-based finding on its id parameter, with replay context.
func seedVerifyStore(t *testing.T, srvURL string) (*c6Store, int64) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &c6Store{home: home, db: filepath.Join(home, "verify.sqlite")}
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = st.db
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	target := srvURL + "/item?id=1"
	base, err := httpmsg.ParseRawRequestWithURL("GET /item?id=1 HTTP/1.1\r\nHost: "+strings.TrimPrefix(srvURL, "http://")+"\r\n\r\n", target)
	if err != nil {
		t.Fatal(err)
	}
	base = base.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nitem")))
	recUUID, err := repo.SaveRecord(ctx, base, "scanner", database.DefaultProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	f := &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ModuleID: "sqli-error-based", ModuleName: "SQL Injection (Error-Based)",
		Severity: "high", Confidence: "firm", FindingHash: "5e5e5e5e5e5e0000000000000000000000000001",
		URL: target, Status: database.StatusTriaged, OriginRecordUUID: recUUID,
		InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.NewRaw("SELECT id FROM findings WHERE finding_hash = ?", f.FindingHash).Scan(ctx, &id); err != nil {
		t.Fatal(err)
	}
	return st, id
}

func TestFindingVerify_EndToEnd(t *testing.T) {
	var fixed atomic.Bool
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !fixed.Load() && strings.ContainsAny(r.URL.Query().Get("id"), `'")\`) {
			_, _ = io.WriteString(w, "You have an error in your SQL syntax; check the manual that "+
				"corresponds to your MySQL server version for the right syntax near 'x' at line 1")
			return
		}
		_, _ = io.WriteString(w, "<html>normal page</html>")
	}))
	defer srv.Close()
	st, id := seedVerifyStore(t, srv.URL)

	// --dry-run sends nothing and writes nothing.
	code, out, errOut := st.run(t, "finding", "verify", itoa(id), "--dry-run", "-j")
	if code != 0 {
		t.Fatalf("dry-run exit = %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["kind"] != "mutation" || doc["dry_run"] != true || doc["changed"] != false || doc["command"] != "finding verify" {
		t.Errorf("dry-run envelope = %v", doc)
	}
	got := items(t, doc)
	if len(got) != 1 {
		t.Fatalf("dry-run items = %v", got)
	}
	plan, _ := got[0]["plan"].(map[string]any)
	if baseline, _ := plan["baseline"].(map[string]any); baseline["source"] != "origin_record" || baseline["request"] == "" {
		t.Errorf("dry-run plan baseline = %v", plan["baseline"])
	}
	if hits.Load() != 0 {
		t.Errorf("dry-run sent %d request(s)", hits.Load())
	}

	// Reproduces: confirmed, stored, status moved by --mark.
	code, out, errOut = st.run(t, "finding", "verify", itoa(id), "--mark", "-j")
	if code != 0 {
		t.Fatalf("verify exit = %d\n%s\n%s", code, out, errOut)
	}
	doc = decodeOne(t, out)
	got = items(t, doc)
	if len(got) != 1 || got[0]["verdict"] != "confirmed" || got[0]["written"] != true {
		t.Fatalf("verify items = %v", got)
	}
	if sc, _ := got[0]["status_change"].(map[string]any); sc["to"] != "confirmed" {
		t.Errorf("--mark status change = %v", got[0]["status_change"])
	}
	if doc["changed"] != true {
		t.Errorf("changed = %v", doc["changed"])
	}

	// The verdict reads back through finding -j.
	code, out, _ = st.run(t, "finding", "--id", itoa(id), "-j")
	if code != 0 {
		t.Fatalf("finding -j exit = %d", code)
	}
	rows := items(t, decodeOne(t, out))
	if len(rows) != 1 || rows[0]["status"] != "confirmed" {
		t.Fatalf("finding rows = %v", rows)
	}
	if v, _ := rows[0]["verification"].(map[string]any); v["verdict"] != "confirmed" || rows[0]["verified_at"] == nil {
		t.Errorf("verification = %v verified_at = %v", rows[0]["verification"], rows[0]["verified_at"])
	}
	if ip, _ := rows[0]["insertion_point"].(map[string]any); ip["name"] != "id" {
		t.Errorf("insertion_point = %v", rows[0]["insertion_point"])
	}

	// Fixed: not_reproduced; --fail-if trips exit 4 after the document.
	fixed.Store(true)
	code, out, _ = st.run(t, "finding", "verify", itoa(id), "--fail-if", "not_reproduced", "-j")
	if code != ExitFailOnGate {
		t.Fatalf("--fail-if exit = %d, want %d\n%s", code, ExitFailOnGate, out)
	}
	if got := items(t, decodeOne(t, out)); len(got) != 1 || got[0]["verdict"] != "not_reproduced" {
		t.Errorf("fixed items = %v", got)
	}

	// --mark cannot combine with --no-write; a miss exits 1.
	if code, _, _ := st.run(t, "finding", "verify", itoa(id), "--mark", "--no-write"); code != ExitUsageError {
		t.Errorf("--mark --no-write exit = %d, want %d", code, ExitUsageError)
	}
	if code, _, _ := st.run(t, "finding", "verify", "424242", "--no-write", "-j"); code != 1 {
		t.Errorf("unknown id exit = %d, want 1", code)
	}
}
