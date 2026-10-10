package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestModuleErrorLedger(t *testing.T) {
	t.Parallel()
	l := newModuleErrorLedger()
	if got := l.snapshot(); got != nil {
		t.Fatalf("empty ledger snapshot = %v, want nil", got)
	}
	for i := int64(1); i <= 3; i++ {
		if n := l.note("ext-a", "exception"); n != i {
			t.Fatalf("note #%d returned %d", i, n)
		}
	}
	l.note("sqli", "timeout")
	got := l.snapshot()
	if got["ext-a"] != 3 || got["sqli"] != 1 || len(got) != 2 {
		t.Fatalf("snapshot = %v", got)
	}
	var nilLedger *moduleErrorLedger
	if n := nilLedger.note("x", "panic"); n != 1 {
		t.Fatalf("nil ledger note = %d, want 1", n)
	}
}

func TestFormatModuleErrorSummary(t *testing.T) {
	t.Parallel()
	if s := formatModuleErrorSummary(nil, "u"); s != "" {
		t.Fatalf("no errors should print nothing, got %q", s)
	}
	got := formatModuleErrorSummary(map[string]int64{"ext-csp": 41, "a": 2, "b": 2, "c": 1}, "scan-1")
	want := "4 modules errored (ext-csp ×41, a ×2, b ×2, …) — see vigolium log scan-1"
	if got != want {
		t.Fatalf("summary =\n %q\nwant\n %q", got, want)
	}
	if got := formatModuleErrorSummary(map[string]int64{"ext-x": 1}, "s"); !strings.HasPrefix(got, "1 module errored (ext-x ×1)") {
		t.Fatalf("singular summary = %q", got)
	}
}

// TestExtensionThrowReachesScanRow runs a real (local) extension-only scan
// whose passive extension throws on every item: the error is counted in
// scans.module_errors under its ext- id, a module.error event names it, and
// the dynamic-assessment phase is partial with extensions_all_failed.
func TestExtensionThrowReachesScanRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	t.Cleanup(srv.Close)

	ext := filepath.Join(t.TempDir(), "thrower.js")
	src := `module.exports = {
  id: "thrower",
  name: "Thrower",
  type: "passive",
  severity: "info",
  confidence: "tentative",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { throw new TypeError("boom from thrower"); }
};`
	if err := os.WriteFile(ext, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.Targets = []string{srv.URL}
	opts.OnlyPhase = "extension"
	opts.ScanUUID = "module-errors-scan"
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = true
	settings.DynamicAssessment.Extensions.ExtensionDir = ""
	settings.DynamicAssessment.Extensions.CustomDir = []string{ext}
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}

	dbCfg := settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "module-errors.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, opts.ScanUUID))
	t.Cleanup(func() { scanevents.Install(prev) })

	r, err := New(opts)
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	r.SetSettings(settings)
	r.SetRepository(repo)
	if err := r.RunNativeScan(); err != nil {
		t.Fatalf("RunNativeScan: %v", err)
	}
	r.Close()

	row, err := repo.GetScanByUUID(context.Background(), opts.ScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	if row.ModuleErrors["ext-thrower"] < 1 {
		t.Fatalf("scans.module_errors = %v, want ext-thrower counted", row.ModuleErrors)
	}

	var da *database.PhaseOutcome
	for i := range row.PhaseOutcomes {
		if row.PhaseOutcomes[i].Phase == string(PhaseDynamicAssessment) {
			da = &row.PhaseOutcomes[i]
		}
	}
	if da == nil || !slices.Contains(da.Reasons, database.ReasonExtensionsAllFailed) {
		t.Fatalf("dynamic-assessment outcome = %+v, want reason %s", da, database.ReasonExtensionsAllFailed)
	}
	if row.Completeness != database.CompletenessPartial {
		t.Errorf("completeness = %q, want partial", row.Completeness)
	}

	var modErr *scanevents.Event
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var ev scanevents.Event
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == scanevents.TypeModuleError && ev.ModuleID == "ext-thrower" {
			modErr = &ev
			break
		}
	}
	if modErr == nil {
		t.Fatalf("no module.error for ext-thrower in:\n%s", buf.String())
	}
	if modErr.ErrorKind != "exception" || modErr.Phase != string(PhaseDynamicAssessment) ||
		modErr.Count == nil || *modErr.Count != 1 || !strings.Contains(modErr.Message, "boom from thrower") {
		t.Errorf("module.error = %+v", *modErr)
	}
}
