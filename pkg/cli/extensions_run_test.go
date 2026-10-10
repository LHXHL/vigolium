package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// seedExtRunStore writes a store holding one record: an HTML admin page.
func seedExtRunStore(t *testing.T) (*c6Store, string) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &c6Store{home: home, db: filepath.Join(home, "extrun.sqlite")}
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
	rr, err := httpmsg.ParseRawRequestWithURL("GET /admin?id=7 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
		"https://app.example.com/admin?id=7")
	if err != nil {
		t.Fatal(err)
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title>Admin console</title></html>")))
	uuid, err := database.NewRepository(db).SaveRecord(ctx, rr, "scanner", database.DefaultProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	return st, uuid
}

// extRunPassiveJS fires on the admin title and reports whether the read-only
// run let it annotate the record (it must not).
const extRunPassiveJS = `module.exports = {
  id: "admin-title", name: "Admin Title", type: "passive", severity: "low", confidence: "firm",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) {
    if (ctx.response.headers.get("content-type").indexOf("html") === -1) return null;
    if (ctx.response.body.indexOf("Admin") === -1) return null;
    var annotated = ctx.record.addRemarks(["admin-title"]);
    return [{ name: "Admin page (" + ctx.record.uuid + ") annotated=" + annotated, url: ctx.request.url }];
  }
};`

// extRunActiveJS calls the network, which an offline run refuses.
const extRunActiveJS = `module.exports = {
  id: "phone-home", name: "Phone Home", type: "active", severity: "medium",
  scanTypes: ["per_request", "per_insertion_point"],
  scanPerRequest: function(ctx) {
    var r = vigolium.http.get(ctx.request.url + "&probe=1");
    return r ? [{ name: "Got " + r.status, url: ctx.request.url }] : null;
  },
  scanPerInsertionPoint: function(ctx, insertion) { return null; }
};`

// decodeFailedResult parses a result document that failed (ok:false with its
// items kept), which decodeOne would validate as an error envelope.
func decodeFailedResult(t *testing.T, stdout string) map[string]any {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	if len(docs) != 1 {
		t.Fatalf("want one document, got %d:\n%s", len(docs), stdout)
	}
	if code, _ := docs[0]["error"].(map[string]any)["code"].(string); code != "failed" {
		t.Errorf("error.code = %q", code)
	}
	return docs[0]
}

func TestExtRun_PassiveOnRecord(t *testing.T) {
	st, uuid := seedExtRunStore(t)
	ext := writeTestFileAt(t, t.TempDir(), "admin_title.js", extRunPassiveJS)

	code, out, errOut := st.run(t, "ext", "run", "--ext", ext, "--record-uuid", uuid, "-j")
	if code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["command"] != "extensions run" || doc["ok"] != true || doc["module_id"] != "ext-admin-title" ||
		doc["record_uuid"] != uuid {
		t.Fatalf("document = %v", doc)
	}
	got := items(t, doc)
	if len(got) != 1 {
		t.Fatalf("items = %v", got)
	}
	name, _ := got[0]["name"].(string)
	if !strings.Contains(name, uuid) || !strings.Contains(name, "annotated=false") {
		t.Errorf("ctx.record.uuid must be the record and annotation must fail read-only: %q", name)
	}
	if got[0]["severity"] != "low" || got[0]["confidence"] != "firm" {
		t.Errorf("module defaults not stamped: %v", got[0])
	}
	if doc["network_calls_blocked"] != float64(0) {
		t.Errorf("network_calls_blocked = %v", doc["network_calls_blocked"])
	}

	// ext eval --record-uuid is the same command and the same document.
	code, out, errOut = st.run(t, "ext", "eval", "--ext", ext, "--record-uuid", uuid[:8], "-j")
	if code != 0 {
		t.Fatalf("eval exit = %d\n%s\n%s", code, out, errOut)
	}
	// The document is ext run's, and names ext run: eval delegates to it.
	if doc := decodeOne(t, out); doc["command"] != "extensions run" ||
		doc["module_id"] != "ext-admin-title" || len(items(t, doc)) != 1 {
		t.Errorf("eval --record-uuid document = %v", doc)
	}
}

func TestExtRun_OfflineBlocksNetwork(t *testing.T) {
	st, uuid := seedExtRunStore(t)
	ext := writeTestFileAt(t, t.TempDir(), "phone_home.js", extRunActiveJS)

	code, out, errOut := st.run(t, "ext", "run", "--ext", ext, "--record-uuid", uuid, "--handler", "scanPerRequest", "-j")
	if code != 1 {
		t.Fatalf("a handler that threw exits 1, got %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeFailedResult(t, out)
	if doc["ok"] != false || doc["network_calls_blocked"] != float64(1) {
		t.Fatalf("document = %v", doc)
	}
	errs, _ := doc["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("errors = %v", doc["errors"])
	}
	if msg, _ := errs[0].(map[string]any)["message"].(string); !strings.Contains(msg, "pass --allow-network") ||
		!strings.Contains(msg, "phone_home.js:5:") || strings.Contains(msg, "github.com") {
		t.Errorf("error message = %q", msg)
	}
	if hs, _ := doc["handlers"].([]any); len(hs) != 1 || hs[0] != "scanPerRequest" {
		t.Errorf("handlers = %v", doc["handlers"])
	}

	// A point that is not there is a usage error naming what is.
	code, out, _ = st.run(t, "ext", "run", "--ext", ext, "--record-uuid", uuid, "--insertion", "URL_PARAM:nope", "-j")
	if code != 2 || !strings.Contains(out, "URL_PARAM:id") {
		t.Errorf("bad --insertion: exit %d\n%s", code, out)
	}
}

func TestExtRun_UsageErrors(t *testing.T) {
	st, uuid := seedExtRunStore(t)
	ext := writeTestFileAt(t, t.TempDir(), "admin_title.js", extRunPassiveJS)

	code, out, _ := st.run(t, "ext", "run", "--ext", ext, "--record-uuid", "00000000-dead-beef-0000-000000000000", "-j")
	if code != 2 || !strings.Contains(out, `"record_not_found"`) {
		t.Errorf("unknown record: exit %d\n%s", code, out)
	}
	code, out, _ = st.run(t, "ext", "run", "--record-uuid", uuid, "-j")
	if code != 2 {
		t.Errorf("no extension: exit %d\n%s", code, out)
	}
	bad := writeTestFileAt(t, t.TempDir(), "bad.js", "module.exports = {")
	code, out, _ = st.run(t, "ext", "run", "--ext", bad, "--record-uuid", uuid, "-j")
	if code != 2 || !strings.Contains(out, `"extension_load_failed"`) {
		t.Errorf("broken extension: exit %d\n%s", code, out)
	}
	code, out, _ = st.run(t, "ext", "eval", "1+1", "--record-uuid", uuid)
	if code != 2 {
		t.Errorf("eval code with --record-uuid: exit %d\n%s", code, out)
	}
}

func TestExtTest_CLI(t *testing.T) {
	st, _ := seedExtRunStore(t)
	testdata := filepath.Join("..", "jsext", "exttest", "testdata")

	code, out, errOut := st.run(t, "ext", "test", filepath.Join(testdata, "fixtures"), "-j")
	if code != 0 {
		t.Fatalf("passing dir: exit %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["command"] != "extensions test" || doc["ok"] != true || doc["failed"] != float64(0) || doc["passed"] != float64(4) {
		t.Fatalf("document = %v", doc)
	}

	code, out, _ = st.run(t, "ext", "test", filepath.Join(testdata, "failing"), "-j")
	if code != 1 {
		t.Fatalf("failing dir: exit %d\n%s", code, out)
	}
	doc = decodeFailedResult(t, out)
	if doc["ok"] != false || doc["failed"] != float64(1) {
		t.Fatalf("document = %v", doc)
	}

	code, out, _ = st.run(t, "ext", "test", filepath.Join(testdata, "failing"))
	if code != 1 || !strings.Contains(out, "not ok 1 - always.js quiet") || !strings.Contains(out, "1..1") {
		t.Errorf("TAP output: exit %d\n%s", code, out)
	}

	// The shipped presets pass their fixtures through the CLI too.
	code, out, errOut = st.run(t, "ext", "test", filepath.Join("..", "..", "public", "presets", "extensions"), "-j")
	if code != 0 {
		t.Fatalf("presets: exit %d\n%s\n%s", code, out, errOut)
	}
}
