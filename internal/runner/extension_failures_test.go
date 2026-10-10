package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// extensionRunner builds a Runner over one counting local target with the
// given --ext paths, the way the CLI hands them over (settings CustomDir).
func extensionRunner(t *testing.T, extPaths []string, allowFailures bool) (*Runner, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.Targets = []string{srv.URL}
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false // no interactsh registration: local traffic only
	settings.DynamicAssessment.Extensions.Enabled = true
	settings.DynamicAssessment.Extensions.ExtensionDir = ""
	settings.DynamicAssessment.Extensions.CustomDir = extPaths
	settings.DynamicAssessment.Extensions.AllowLoadFailures = allowFailures

	r, err := New(opts)
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	r.SetSettings(settings)
	// Discard, not Close: Close waits for a RunNativeScan that a test which
	// only builds infrastructure never starts.
	t.Cleanup(r.Discard)
	return r, &hits
}

func captureEvents(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, "scan-ext"))
	t.Cleanup(func() { scanevents.Install(prev) })
	return &buf
}

// TestExplicitExtensionFailureAbortsBeforeTraffic: an --ext file that does not
// load stops the scan with *ExtensionLoadError (extension_load_failed) before
// a single request reaches the target, and announces extension.failed.
func TestExplicitExtensionFailureAbortsBeforeTraffic(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.js")
	if err := os.WriteFile(bad, []byte(`throw new Error("broken at load");`), 0o644); err != nil {
		t.Fatal(err)
	}
	events := captureEvents(t)
	r, hits := extensionRunner(t, []string{bad}, false)

	err := r.RunNativeScan()
	var loadErr *ExtensionLoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("err = %v, want *ExtensionLoadError", err)
	}
	if loadErr.Code() != apicontract.CodeExtensionLoadFailed {
		t.Errorf("code = %s", loadErr.Code())
	}
	if len(loadErr.Failures) != 1 || loadErr.Failures[0].Path != bad {
		t.Errorf("failures = %+v", loadErr.Failures)
	}
	if !strings.Contains(err.Error(), "--ext-allow-failures") {
		t.Errorf("message %q must name the escape hatch", err.Error())
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("target received %d request(s) before the abort", n)
	}

	var ev map[string]any
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["type"] == scanevents.TypeExtensionFailed {
			ev = m
		}
	}
	if ev == nil {
		t.Fatalf("no extension.failed event in %q", events.String())
	}
	if ev["path"] != bad || ev["stage"] != "metadata" || ev["explicit"] != true {
		t.Errorf("extension.failed = %v", ev)
	}
}

// TestExplicitExtensionFailureAllowed: with --ext-allow-failures the failure
// is reported but infrastructure builds and the scan may proceed.
func TestExplicitExtensionFailureAllowed(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.js")
	if err := os.WriteFile(bad, []byte(`module.exports = {`), 0o644); err != nil {
		t.Fatal(err)
	}
	events := captureEvents(t)
	r, _ := extensionRunner(t, []string{bad}, true)

	infra, err := r.buildInfrastructure(t.Context(), BuildNativeScanPlan(r.options))
	if err != nil {
		t.Fatalf("buildInfrastructure: %v", err)
	}
	defer infra.Close()
	if infra.jsEngine == nil || len(infra.jsEngine.Failures()) != 1 {
		t.Fatalf("engine failures not kept for the scan row: %+v", infra.jsEngine)
	}
	if !strings.Contains(events.String(), `"stage":"compile"`) {
		t.Errorf("extension.failed not emitted: %s", events.String())
	}
}
