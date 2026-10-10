package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// Scope admission ("scope never silently drops everything"): a scan whose every
// target the configured scope refuses exits 1 with error.code
// no_targets_in_scope and sends NOTHING. Each case re-execs the test binary as
// the real CLI (cobra parse, exit-code mapping) against a local httptest server
// that counts requests; zero requests is the property under test.

const a3ChildEnv = "VIGOLIUM_A3_SCOPE_ARGS"

// TestScopeAdmissionChild is the child half of runA3: the real Execute().
func TestScopeAdmissionChild(t *testing.T) {
	raw := os.Getenv(a3ChildEnv)
	if raw == "" {
		t.Skip("child process helper")
	}
	os.Args = append([]string{"vigolium"}, strings.Split(raw, "\x1f")...)
	Execute()
	os.Exit(0)
}

// a3Home is a throwaway HOME with the first-run marker present (no dependency
// bootstrap) and a config whose scope admits only hostInclude.
func a3Home(t *testing.T, hostInclude string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".vigolium")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, initMarkerFileName), []byte("ok"), 0o600))
	cfg := "scope:\n  host:\n    include: [\"" + hostInclude + "\"]\n    exclude: []\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vigolium-configs.yaml"), []byte(cfg), 0o600))
	return home
}

func runA3(t *testing.T, home string, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScopeAdmissionChild$", "-test.v=false")
	env := []string{a3ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	default:
		t.Fatalf("run child: %v", err)
		return -1, "", ""
	}
}

// countingServer counts every request it receives.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// errorCode extracts the failure code of a -j run's ONE stdout document: the
// scan document's errors[0].code when the scan got far enough to have one,
// else the error envelope's error.code.
func errorCode(t *testing.T, stdout string) string {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, "exactly one document on stdout:\n%s", stdout)
	var doc struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	raw, err := json.Marshal(docs[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &doc))
	if doc.Error.Code != "" {
		return doc.Error.Code
	}
	require.NotEmpty(t, doc.Errors, "a failed scan document carries errors[]:\n%s", stdout)
	return doc.Errors[0].Code
}

// a3Repo opens the sqlite store a child run wrote.
func a3Repo(t *testing.T, path string) *database.Repository {
	t.Helper()
	cfg := config.DefaultSettings().Database
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

func TestScanAllTargetsOutOfScopeFailsAndSendsNothing(t *testing.T) {
	srv, hits := countingServer(t)
	target := srv.URL + "/"
	cases := map[string][]string{
		"scan -S":            {"scan", "-t", target, "-S", "-j"},
		"scan --db":          {"scan", "-t", target, "-j"},
		"scan-url direct -S": {"scan-url", target, "-S", "-j", "-m", "security-headers-missing"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			home := a3Home(t, "nomatch.example")
			if !strings.Contains(strings.Join(args, " "), " -S") {
				args = append(args, "--db", filepath.Join(home, "a3.sqlite"))
			}
			code, stdout, stderr := runA3(t, home, args...)
			require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.Equal(t, string(apicontract.CodeNoTargetsInScope), errorCode(t, stdout))
			assert.Contains(t, stdout, config.ScopeRuleHostInclude, "the error names the rule")
			assert.Zero(t, hits.Load(), "a refused target must not be contacted")
		})
	}
}

// scan-url on the direct path (no -S/-o) enforces config scope too: the result
// document is written (stop_reason, targets_rejected, scan_uuid), the row is
// stored failed with stop_reason no_targets_in_scope, and the exit is 1.
func TestScanURLDirectOutOfScope(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "nomatch.example")
	dbPath := filepath.Join(home, "a3.sqlite")

	code, stdout, stderr := runA3(t, home, "scan-url", srv.URL+"/", "-j", "--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Zero(t, hits.Load(), "a refused target must not be contacted")

	doc := decodeOneScanDoc(t, stdout)
	assert.Equal(t, "failed", doc.Status)
	assert.Equal(t, database.ReasonNoTargetsInScope, doc.StopReason)
	require.Len(t, doc.Targets, 1)
	assert.False(t, doc.Targets[0].Admitted)
	assert.Equal(t, scanDocReasonOutOfScope, doc.Targets[0].Reason)
	assert.Equal(t, config.ScopeRuleHostInclude, doc.Targets[0].Code)
	require.NotEmpty(t, doc.ScanUUID)
	assert.Empty(t, doc.Items)
	require.NotEmpty(t, doc.Errors)
	assert.Equal(t, apicontract.CodeNoTargetsInScope, doc.Errors[0].Code)

	row, err := a3Repo(t, dbPath).GetScanByUUID(context.Background(), doc.ScanUUID)
	require.NoError(t, err)
	assert.Equal(t, "failed", row.Status)
	assert.Equal(t, database.ReasonNoTargetsInScope, row.StopReason)

	// scan-request takes the same direct path.
	reqFile := filepath.Join(home, "req.txt")
	require.NoError(t, os.WriteFile(reqFile, []byte("GET /x HTTP/1.1\r\nHost: example.invalid\r\n\r\n"), 0o600))
	code, stdout, stderr = runA3(t, home, "scan-request", "-i", reqFile, "-t", srv.URL, "-j", "--db", dbPath, "-m", "security-headers-missing")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	reqDoc := decodeOneScanDoc(t, stdout)
	assert.Equal(t, "scan-request", reqDoc.Command)
	assert.Equal(t, database.ReasonNoTargetsInScope, reqDoc.StopReason)
	assert.Zero(t, hits.Load(), "a refused request must not be sent")

	// --ignore-scope is the escape hatch: the same target is scanned.
	code, stdout, stderr = runA3(t, home, "scan-url", srv.URL+"/", "-j", "--db", dbPath, "-m", "security-headers-missing", "--ignore-scope")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Positive(t, hits.Load(), "--ignore-scope scans the target")
}

// A batch where scope refuses some inputs scans the rest and exits 0; the
// refused input is reported in the scan document's targets[], not sent.
func TestScanURLDirectPartialBatch(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	refused := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/"

	code, stdout, stderr := runA3(t, home, "scan-url", "-t", srv.URL+"/", "-t", refused, "-j",
		"--db", filepath.Join(home, "a3.sqlite"), "-m", "security-headers-missing")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Positive(t, hits.Load(), "the admitted input is scanned")

	doc := decodeOneScanDoc(t, stdout)
	require.Len(t, doc.Targets, 2)
	assert.True(t, doc.Targets[0].Admitted)
	assert.Empty(t, doc.Targets[0].Reason)
	assert.False(t, doc.Targets[1].Admitted)
	assert.Equal(t, scanDocReasonOutOfScope, doc.Targets[1].Reason)
	assert.Equal(t, refused, doc.Targets[1].Target)
	assert.Len(t, doc.ScanUUIDs, 2, "one row per unpinned input")
	assert.Contains(t, doc.Reasons, database.ReasonTargetsOutOfScope)
}

// --events: scan.started carries the admission counts before the run fails,
// and scan.finished the stop reason; the row keeps the preflight tally.
func TestScanEventsCarryAdmission(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "nomatch.example")
	dbPath := filepath.Join(home, "a3.sqlite")

	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "--events", "ndjson", "--db", dbPath)
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Zero(t, hits.Load())

	events := map[string]map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		var ev map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev), sc.Text())
		if typ, _ := ev["type"].(string); typ != "" {
			events[typ] = ev
		}
	}
	started, finished := events["scan.started"], events["scan.finished"]
	require.NotNil(t, started, stdout)
	require.NotNil(t, finished, stdout)
	assert.Equal(t, float64(0), started["targets_admitted"])
	assert.Equal(t, float64(1), started["targets_rejected"])
	assert.Equal(t, "failed", finished["status"])
	assert.Equal(t, database.ReasonNoTargetsInScope, finished["stop_reason"])
	assert.Equal(t, float64(1), finished["targets_rejected"])

	uuid, _ := started["scan_uuid"].(string)
	require.NotEmpty(t, uuid)
	row, err := a3Repo(t, dbPath).GetScanByUUID(context.Background(), uuid)
	require.NoError(t, err)
	assert.Equal(t, "failed", row.Status)
	assert.Equal(t, database.ReasonNoTargetsInScope, row.StopReason)
	require.NotEmpty(t, row.PhaseOutcomes)
	pre := row.PhaseOutcomes[0]
	assert.Equal(t, string(runner.PhasePreflight), pre.Phase)
	require.NotNil(t, pre.Targets)
	assert.Equal(t, 1, pre.Targets.Requested)
	assert.Equal(t, 0, pre.Targets.Admitted)
}

// The banner/event admission reads the targets the scan is about to seed, and
// stays out of inputs that are not a target list.
func TestScanTargetAdmissionInputs(t *testing.T) {
	settings := config.DefaultSettings()
	settings.Scope.Host = config.ScopeRule{Include: []string{"in.test"}}

	file := filepath.Join(t.TempDir(), "targets.txt")
	require.NoError(t, os.WriteFile(file, []byte("http://out.test/\n"), 0o600))

	origInput := globalInput
	t.Cleanup(func() { globalInput = origInput })
	globalInput = ""

	opts := types.DefaultOptions()
	opts.Targets = []string{"http://in.test/"}
	opts.TargetsFilePaths = []string{file}
	adm := scanTargetAdmission(settings, opts, false)
	require.NotNil(t, adm)
	assert.Equal(t, []string{"http://in.test/"}, adm.Admitted)
	require.Len(t, adm.Rejected, 1)
	assert.Equal(t, "http://out.test/", adm.Rejected[0].Target)

	globalInput = "spec.yaml"
	assert.Nil(t, scanTargetAdmission(settings, opts, false), "-i: the targets are a base URL, not the input")
}

func TestCodedScanErrorClassifiesNoTargetsInScope(t *testing.T) {
	adm := types.TargetAdmission{Rejected: []types.TargetVerdict{{Target: "http://a.test/", Host: "a.test", Rule: config.ScopeRuleHostInclude}}}
	err := codedScanError(&runner.TargetsRejectedError{Admission: adm})
	assert.ErrorIs(t, err, runner.ErrNoTargetsInScope)
	assert.Equal(t, ExitError, classifyExitCode(err))
	assert.Equal(t, apicontract.CodeNoTargetsInScope, classifyErrorCode(err, ExitError))
	assert.Contains(t, err.Error(), "config validate")

	plain := errors.New("boom")
	assert.Same(t, plain, codedScanError(plain))
}
