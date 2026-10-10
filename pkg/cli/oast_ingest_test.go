package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestOASTIngest_EndToEnd runs `oast ingest` through Execute() against a store
// holding one planted payload: the callback carrying its nonce becomes a
// finding of the planting scan, the other callback is counted as unmatched.
func TestOASTIngest_EndToEnd(t *testing.T) {
	st := seedC6Store(t)
	const nonce = "cv7k2m9q4r8s1t3u5v6a"

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = st.db
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.NewRepository(db).SaveOASTPayloads(context.Background(), []*database.OASTPayload{{
		Nonce: nonce, ProjectUUID: database.DefaultProjectUUID, ScanUUID: st.s1, Class: "xxe",
		ModuleID: "xxe-generic", TargetURL: "https://app.example/upload", Param: "body", RequestHash: "rh",
	}}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	log := filepath.Join(st.home, "callbacks.jsonl")
	lines := `{"protocol":"http","unique-id":"x","full-id":"x","raw-request":"GET /` + nonce + `.dtd HTTP/1.1\r\nHost: cb.example.com\r\nUser-Agent: Java/17\r\n\r\n","remote-address":"203.0.113.4","timestamp":"2026-10-10T10:00:00Z"}
{"protocol":"dns","unique-id":"y","full-id":"cv00000000000000000a.cb.example.com","remote-address":"8.8.8.8","timestamp":"2026-10-10T10:00:01Z"}
`
	if err := os.WriteFile(log, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := st.run(t, "oast", "ingest", log, "--format", "interactsh-json", "-j")
	if code != 0 {
		t.Fatalf("ingest exit = %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	if doc["kind"] != "mutation" || doc["command"] != "oast ingest" || doc["changed"] != true {
		t.Errorf("envelope = kind %v command %v changed %v", doc["kind"], doc["command"], doc["changed"])
	}
	if doc["matched"] != float64(1) || doc["unmatched"] != float64(1) || doc["callbacks"] != float64(2) {
		t.Errorf("counters = matched %v unmatched %v callbacks %v", doc["matched"], doc["unmatched"], doc["callbacks"])
	}
	got := items(t, doc)
	if len(got) != 1 || got[0]["module_id"] != "xxe-generic" || got[0]["param"] != "body" ||
		got[0]["scan_uuid"] != st.s1 || got[0]["severity"] != "high" {
		t.Fatalf("items = %v", got)
	}

	// The finding reads back on the planting scan.
	code, out, _ = st.run(t, "finding", "xxe-generic", "--scan-uuid", st.s1, "-j")
	if code != 0 {
		t.Fatalf("finding exit = %d\n%s", code, out)
	}
	if found := items(t, decodeOne(t, out)); len(found) != 1 {
		t.Errorf("findings on the planting scan = %v", found)
	}

	// Again: nothing new.
	code, out, _ = st.run(t, "oast", "ingest", log, "--format", "interactsh-json", "-j")
	if doc := decodeOne(t, out); code != 0 || doc["duplicates"] != float64(1) || len(items(t, doc)) != 0 {
		t.Errorf("re-ingest: exit %d doc %v", code, doc)
	}
}

func TestOASTIngest_UsageErrors(t *testing.T) {
	st := seedC6Store(t)
	log := filepath.Join(st.home, "cb.log")
	if err := os.WriteFile(log, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no format":             {"oast", "ingest", log},
		"bad format":            {"oast", "ingest", log, "--format", "jsonl"},
		"protocol on json":      {"oast", "ingest", log, "--format", "interactsh-json", "--protocol", "http"},
		"bad protocol":          {"oast", "ingest", log, "--format", "raw-log", "--protocol", "gopher"},
		"missing file":          {"oast", "ingest", filepath.Join(st.home, "nope.log"), "--format", "raw-log"},
		"malformed interactsh":  {"oast", "ingest", log, "--format", "interactsh-json"},
		"glob-db is a tmp copy": {"oast", "ingest", log, "--format", "raw-log", "--glob-db", "*.sqlite"},
	} {
		if code, out, errOut := st.run(t, append(args, "-j")...); code != ExitUsageError {
			t.Errorf("%s: exit %d, want %d\n%s\n%s", name, code, ExitUsageError, out, errOut)
		}
	}
}
