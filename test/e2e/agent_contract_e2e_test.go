//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// The agent machine contract (plan B7), driven end to end through the real
// binary against a local OpenAI-compatible stub: no real LLM, no network
// beyond loopback.

// stubLLM is an OpenAI-compatible /chat/completions endpoint. The preflight
// ping ("Reply with the single word OK") is answered at once; every other
// request gets reply, or — with stall — blocks until the client gives up.
type stubLLM struct {
	srv   *httptest.Server
	reply atomic.Value // string
	stall atomic.Bool
	calls atomic.Int32
}

func newStubLLM(t *testing.T) *stubLLM {
	t.Helper()
	s := &stubLLM{}
	s.reply.Store("hello from the stub")
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		text := s.reply.Load().(string)
		if strings.Contains(string(body), "Reply with the single word OK") {
			text = "OK"
		} else if s.stall.Load() {
			<-r.Context().Done()
			return
		}
		chunk, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": text}}}})
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3}}`)
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// agentFixture is a temp HOME, a config pointing olium at the stub, and a DB.
type agentFixture struct {
	bin, home, config, db string
	stub                  *stubLLM
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	f := &agentFixture{bin: buildVigoliumBinary(t), home: t.TempDir(), stub: newStubLLM(t)}
	f.db = filepath.Join(t.TempDir(), "agent.sqlite")
	f.config = filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	require.NoError(t, os.WriteFile(f.config, []byte(fmt.Sprintf(`agent:
  sessions_dir: %s
  olium:
    provider: openai-compatible
    model: stub-model
    preflight_timeout: 10s
    custom_provider:
      base_url: %s/v1
      model_id: stub-model
`, filepath.Join(f.home, "sessions"), f.stub.srv.URL)), 0o600))
	return f
}

// run executes the binary and returns stdout, stderr and the exit code.
func (f *agentFixture) run(t *testing.T, timeout time.Duration, extraEnv []string, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.bin, append([]string{"--config", f.config, "--db", f.db, "--skip-dependency-check"}, args...)...)
	cmd.Env = append(os.Environ(),
		"HOME="+f.home,
		"VIGOLIUM_PROJECT_NAME=", "VIGOLIUM_PROJECT_UUID=", "VIGOLIUM_DB_PATH=", "VIGOLIUM_DB=",
		"VIGOLIUM_DISABLE_UPDATE_CHECK=1", "NO_COLOR=1",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v\nstderr: %s", args, err, stderr.String())
	}
	return stdout.String(), terminal.StripANSI(stderr.String()), code
}

// oneDocument parses stdout as exactly one JSON document.
func oneDocument(t *testing.T, stdout string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Lenf(t, lines, 1, "stdout must carry exactly one document, got:\n%s", stdout)
	var doc map[string]any
	require.NoErrorf(t, json.Unmarshal([]byte(lines[0]), &doc), "stdout: %s", stdout)
	return doc
}

func agenticScanStatus(t *testing.T, dbPath, uuid string) string {
	t.Helper()
	db := openSQLiteDB(t, dbPath)
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		"SELECT status FROM agentic_scans WHERE uuid = ?", uuid).Scan(&status))
	return status
}

func TestAgentContract_ListAgentsAndSession(t *testing.T) {
	f := newAgentFixture(t)

	out, stderr, code := f.run(t, time.Minute, nil, "agent", "--list-agents", "-j")
	require.Equalf(t, 0, code, "stderr: %s", stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, "read", doc["kind"])
	assert.Equal(t, "openai-compatible", doc["active"])
	assert.Equal(t, "config", doc["active_source"])
	assert.NotEmpty(t, doc["items"])

	out, stderr, code = f.run(t, time.Minute, nil, "agent", "session", "-j")
	require.Equalf(t, 0, code, "stderr: %s", stderr)
	doc = oneDocument(t, out)
	assert.Equal(t, "read", doc["kind"])
	assert.Equal(t, []any{}, doc["items"])
}

func TestAgentContract_QueryJSON(t *testing.T) {
	f := newAgentFixture(t)
	out, stderr, code := f.run(t, 2*time.Minute, nil, "agent", "query", "-j", "say hi")
	require.Equalf(t, 0, code, "stderr: %s", stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, "agent query", doc["command"])
	uuid, _ := doc["agentic_scan_uuid"].(string)
	require.NotEmpty(t, uuid, "the query's run handle is in the envelope")
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].(map[string]any)["raw_output"], "hello from the stub")
	assert.Contains(t, stderr, uuid, "the run handle is printed to stderr too")
	assert.Equal(t, "completed", agenticScanStatus(t, f.db, uuid))

	// The session list now shows it.
	out, _, code = f.run(t, time.Minute, nil, "agent", "session", "-j")
	require.Equal(t, 0, code)
	assert.Contains(t, out, uuid)
}

func TestAgentContract_TriageNoWrite(t *testing.T) {
	f := newAgentFixture(t)
	// Bootstrap the schema, then seed one finding.
	_, stderr, code := f.run(t, time.Minute, nil, "agent", "session", "-j")
	require.Equalf(t, 0, code, "stderr: %s", stderr)
	db := openSQLiteDB(t, f.db)
	repo := database.NewRepository(db)
	require.NoError(t, repo.SaveFindingDirect(context.Background(), &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ModuleID: "m", ModuleName: "M",
		Severity: "high", Confidence: "firm", FindingHash: "b7-triage", Description: "orig",
		URL: "http://127.0.0.1:9/x",
	}))
	var id int64
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT id FROM findings WHERE finding_hash = 'b7-triage'").Scan(&id))
	_ = db.Close()

	f.stub.reply.Store(`{"verdict":"false_positive","reasoning":"static content"}`)
	out, stderr, code := f.run(t, 2*time.Minute, nil, "agent", "triage", strconv.FormatInt(id, 10), "--no-write", "--no-probe", "-j")
	require.Equalf(t, 0, code, "stderr: %s", stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, "mutation", doc["kind"])
	assert.Equal(t, false, doc["changed"])
	item := doc["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "false_positive", item["verdict"])
	assert.Equal(t, false, item["written"])
	assert.Equal(t, "high", item["new_severity"])

	db = openSQLiteDB(t, f.db)
	var sev, status string
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT severity, status FROM findings WHERE id = ?", id).Scan(&sev, &status))
	assert.Equal(t, "high", sev)
	assert.NotEqual(t, "false_positive", status, "--no-write writes nothing")
}

// TestAgentContract_AutopilotTimeoutExit5: a wall-clock stop is exit 5 with
// status timed_out in the document and "timeout" in the database.
func TestAgentContract_AutopilotTimeoutExit5(t *testing.T) {
	f := newAgentFixture(t)
	f.stub.stall.Store(true)
	target := projectScopingTarget(t)
	out, stderr, code := f.run(t, 3*time.Minute, nil, "agent", "autopilot", "-t", target.URL,
		"--no-prescan", "--no-skill-filter", "--prior-context", "off", "--max-duration", "3s", "-j")
	require.Equalf(t, 5, code, "stdout: %s\nstderr: %s", out, stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, "scan", doc["kind"])
	assert.Equal(t, "timed_out", doc["status"])
	assert.Equal(t, "timed_out", doc["stop_reason"])
	uuid, _ := doc["agentic_scan_uuid"].(string)
	require.NotEmpty(t, uuid)
	assert.Equal(t, "timeout", agenticScanStatus(t, f.db, uuid))
}

// TestAgentContract_ProviderMissing: a provider that cannot be built is exit 1
// with error.code provider_missing.
func TestAgentContract_ProviderMissing(t *testing.T) {
	f := newAgentFixture(t)
	out, stderr, code := f.run(t, time.Minute, []string{"OPENAI_API_KEY="},
		"agent", "query", "-j", "--provider", "openai-api-key", "say hi")
	require.Equalf(t, 1, code, "stdout: %s\nstderr: %s", out, stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, false, doc["ok"])
	assert.Equal(t, "provider_missing", doc["error"].(map[string]any)["code"])
}

// TestAgentContract_AuditRequiresSource: `audit` with no --source is a usage
// error (it used to audit the working directory).
func TestAgentContract_AuditRequiresSource(t *testing.T) {
	f := newAgentFixture(t)
	out, stderr, code := f.run(t, time.Minute, nil, "audit", "-j")
	require.Equalf(t, 2, code, "stdout: %s\nstderr: %s", out, stderr)
	doc := oneDocument(t, out)
	assert.Equal(t, "usage_error", doc["error"].(map[string]any)["code"])
	assert.Contains(t, doc["error"].(map[string]any)["message"], "--source .")
}
