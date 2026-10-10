package cli

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/autopilot"
)

// TestAgentStreamSinkUsedEverywhere: an agent run's live stream must never
// land on stdout under -j, where the one result document goes. Every
// `X.StreamWriter = …` assignment in pkg/cli takes agentStreamSink() (or the
// runtime-log tee wrapped around it), and no StreamWriter/Out field is ever
// handed os.Stdout directly.
func TestAgentStreamSinkUsedEverywhere(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "StreamWriter" || i >= len(n.Rhs) {
						continue
					}
					checked++
					if !isAgentSinkExpr(n.Rhs[i]) {
						t.Errorf("%s: StreamWriter assigned %s; route it through agentStreamSink()",
							fset.Position(n.Pos()), exprString(n.Rhs[i]))
					}
				}
			case *ast.KeyValueExpr:
				key, ok := n.Key.(*ast.Ident)
				if !ok || (key.Name != "StreamWriter" && key.Name != "Out") {
					return true
				}
				if isOSStdout(n.Value) {
					t.Errorf("%s: %s: os.Stdout; route it through agentStreamSink()", fset.Position(n.Pos()), key.Name)
				}
			}
			return true
		})
	}
	require.Greater(t, checked, 2, "the walk found no StreamWriter assignments; it is not looking at pkg/cli")
}

// isAgentSinkExpr accepts agentStreamSink() and the tee teeToRuntimeLog
// returns (which wraps the sink it was given).
func isAgentSinkExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.CallExpr:
		id, ok := v.Fun.(*ast.Ident)
		return ok && id.Name == "agentStreamSink"
	case *ast.Ident:
		return v.Name == "tee"
	}
	return false
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "()"
	}
	return "<expr>"
}

// TestAgentRunStatusMapping: the database status and the document status come
// from one function and differ only in the spelling of a timeout.
func TestAgentRunStatusMapping(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name               string
		end                database.AgenticRunEnd
		db, json, stop     string
		completeness       string
		exitCode           int
		incompleteErrorish apicontract.ErrorCode
	}{
		{"clean", database.AgenticRunEnd{}, "completed", "completed", "", database.CompletenessComplete, 0, ""},
		{"degraded", database.AgenticRunEnd{Degraded: true}, "completed_with_warnings", "completed_with_warnings", "", database.CompletenessComplete, 0, ""},
		{"timeout", database.AgenticRunEnd{TimedOut: true}, "timeout", "timed_out", "timed_out", database.CompletenessPartial, ExitIncomplete, apicontract.CodeTimedOut},
		{"budget", database.AgenticRunEnd{BudgetExhausted: true}, "budget_exhausted", "budget_exhausted", "budget_exhausted", database.CompletenessPartial, ExitIncomplete, apicontract.CodeBudgetExhausted},
		{"some drivers failed", database.AgenticRunEnd{FailedDrivers: 1, TotalDrivers: 2}, "completed_with_errors", "completed_with_errors", "partial", database.CompletenessPartial, ExitIncomplete, apicontract.CodePartial},
		{"all drivers failed", database.AgenticRunEnd{Err: boom, FailedDrivers: 2, TotalDrivers: 2}, "failed", "failed", "", database.CompletenessPartial, 0, ""},
		{"error", database.AgenticRunEnd{Err: boom}, "failed", "failed", "", database.CompletenessPartial, 0, ""},
		{"interrupt", database.AgenticRunEnd{Err: boom, Cancelled: true}, "cancelled", "cancelled", "interrupted", database.CompletenessPartial, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, js := agentRunStatus(tc.end)
			assert.Equal(t, tc.db, db)
			assert.Equal(t, tc.json, js)
			assert.Equal(t, tc.stop, agentRunStopReason(js))
			assert.Equal(t, tc.completeness, agentRunCompleteness(js))
			assert.Contains(t, database.TerminalAgenticScanStatuses, db, "every status a run ends in must be terminal")
			err := agentRunExitError(js, "u", "")
			if tc.exitCode == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.exitCode, classifyExitCode(err))
			assert.Equal(t, tc.incompleteErrorish, classifyErrorCode(err, classifyExitCode(err)))
		})
	}
}

// TestAutopilotRunEnd: a wall-clock or budget stop is a designed stop, not a
// failure, whichever way the loop reported it.
func TestAutopilotRunEnd(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	live := context.Background()
	interrupted, stop := context.WithCancel(context.Background())
	stop()

	end := autopilotRunEnd(expired, errors.New("autopilot engine: context deadline exceeded"), "", false)
	assert.True(t, end.TimedOut)
	assert.NoError(t, end.Err)

	end = autopilotRunEnd(live, nil, autopilot.BudgetWallTime, false)
	assert.True(t, end.TimedOut, "the loop's own MaxWallTime stop is a timeout")

	end = autopilotRunEnd(live, nil, autopilot.BudgetTokens, false)
	assert.True(t, end.BudgetExhausted)
	assert.False(t, end.TimedOut)

	end = autopilotRunEnd(interrupted, errors.New("context canceled"), "", false)
	assert.True(t, end.Cancelled)
	assert.Error(t, end.Err)

	end = autopilotRunEnd(live, nil, "", true)
	db, _ := agentRunStatus(end)
	assert.Equal(t, "completed_with_warnings", db)
}

func withAgentJSONOutput(t *testing.T) {
	t.Helper()
	prevJSON, prevLatch := globalJSON, jsonResultEmitted
	globalJSON = true
	jsonResultEmitted = false
	t.Cleanup(func() { globalJSON, jsonResultEmitted = prevJSON, prevLatch })
}

// TestEmitAgentRunDocumentWithoutRepo: a run with no store still prints its
// one document, saying persisted:false, with what it holds in memory.
func TestEmitAgentRunDocumentWithoutRepo(t *testing.T) {
	withAgentJSONOutput(t)
	var exitErr error
	out := captureStdout(t, func() {
		exitErr = emitAgentRunDocument(&agentRunOutcome{
			Command:         "agent autopilot",
			Mode:            "autopilot",
			AgenticScanUUID: "run-1",
			SessionDir:      "/tmp/session",
			End:             database.AgenticRunEnd{TimedOut: true},
			FindingCount:    3,
			Budget:          agentRunBudget{MaxCommands: 10, Stop: autopilot.BudgetWallTime, Exhausted: true},
		})
	})
	require.Error(t, exitErr)
	assert.Equal(t, ExitIncomplete, classifyExitCode(exitErr))

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 1, "exactly one document on stdout")
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &doc))
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, "scan", doc["kind"])
	assert.Equal(t, "agent autopilot", doc["command"])
	assert.Equal(t, false, doc["persisted"])
	assert.Equal(t, "timed_out", doc["status"])
	assert.Equal(t, "partial", doc["completeness"])
	assert.Equal(t, "timed_out", doc["stop_reason"])
	assert.Equal(t, "run-1", doc["agentic_scan_uuid"])
	assert.Equal(t, "/tmp/session", doc["session_dir"])
	assert.EqualValues(t, 3, doc["total"])
	assert.Equal(t, []any{}, doc["items"])
	assert.NotContains(t, doc, "query", "nothing persisted, so no follow-up query")
	budget := doc["budget"].(map[string]any)
	assert.Equal(t, true, budget["exhausted"])
	assert.Equal(t, "wall_time", budget["stop"])
	assert.Equal(t, []any{}, doc["errors"])
}

// TestAgentRunDocumentTreeAggregation: the document counts findings across
// the whole run tree (parent + nested driver children) and embeds the most
// severe first.
func TestAgentRunDocumentTreeAggregation(t *testing.T) {
	db := newExportTestDB(t)
	ctx := context.Background()
	project := database.DefaultProjectUUID
	parent, child := "parent-scan-uuid", "child-scan-uuid"
	for _, sc := range []database.AgenticScan{
		{UUID: parent, ProjectUUID: project, Mode: "audit", AgentName: "audit"},
		{UUID: child, ProjectUUID: project, Mode: "audit", AgentName: "audit", ParentAgenticScanUUID: parent},
	} {
		s := sc
		_, err := db.NewInsert().Model(&s).Exec(ctx)
		require.NoError(t, err)
	}
	repo := database.NewRepository(db)
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, AgenticScanUUID: parent, ModuleID: "m1", ModuleName: "M1",
		Severity: "high", Confidence: "firm", FindingHash: "h1",
	}))
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, AgenticScanUUID: child, ModuleID: "m2", ModuleName: "M2",
		Severity: "critical", Confidence: "firm", FindingHash: "h2",
	}))
	require.ElementsMatch(t, []string{parent, child}, resolveAgenticScanTree(ctx, db, parent))

	withAgentJSONOutput(t)
	out := captureStdout(t, func() {
		require.NoError(t, emitAgentRunDocument(&agentRunOutcome{
			Command: "agent audit", Mode: "audit", AgenticScanUUID: parent,
			ProjectUUID: project, Repo: repo,
			End: database.AgenticRunEnd{TotalDrivers: 1},
		}))
	})
	var doc struct {
		Status    string           `json:"status"`
		Persisted bool             `json:"persisted"`
		Total     int64            `json:"total"`
		Counts    map[string]int64 `json:"counts_by_severity"`
		Items     []map[string]any `json:"items"`
		Query     string           `json:"query"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Equal(t, "completed", doc.Status)
	assert.True(t, doc.Persisted)
	assert.EqualValues(t, 2, doc.Total)
	assert.EqualValues(t, 1, doc.Counts["critical"])
	assert.EqualValues(t, 1, doc.Counts["high"])
	require.Len(t, doc.Items, 2)
	assert.Equal(t, "critical", doc.Items[0]["severity"])
	assert.Contains(t, doc.Query, "--agentic-scan "+parent)
}

// TestEmitAgentRunDocumentNoopWithoutJSON: the human path prints its own
// summary; the document is -j only (the exit code still applies).
func TestEmitAgentRunDocumentNoopWithoutJSON(t *testing.T) {
	prev := globalJSON
	globalJSON = false
	t.Cleanup(func() { globalJSON = prev })
	var err error
	out := captureStdout(t, func() {
		err = emitAgentRunDocument(&agentRunOutcome{Mode: "swarm", AgenticScanUUID: "x", End: database.AgenticRunEnd{BudgetExhausted: true}})
	})
	assert.Empty(t, out)
	assert.Equal(t, ExitIncomplete, classifyExitCode(err))
}

func seedTriageFinding(t *testing.T, repo *database.Repository, severity string) *database.Finding {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ModuleID: "m", ModuleName: "M",
		Severity: severity, Confidence: "firm", FindingHash: "triage-" + severity, Description: "orig",
	}))
	var f database.Finding
	require.NoError(t, repo.DB().NewSelect().Model(&f).Where("finding_hash = ?", "triage-"+severity).Scan(ctx))
	return &f
}

// TestApplyTriageVerdictKeepsSeverity: a false positive keeps the severity it
// was reported with (its status is what drops it from gates), a confirmed
// verdict writes "confirmed", and inconclusive writes nothing.
func TestApplyTriageVerdictKeepsSeverity(t *testing.T) {
	ctx := context.Background()
	repo := database.NewRepository(newExportTestDB(t))

	fp := seedTriageFinding(t, repo, "high")
	require.NoError(t, applyTriageVerdict(ctx, repo, database.DefaultProjectUUID, fp,
		&agent.TriageConfirmResult{Verdict: agent.TriageVerdictFalsePositive, Reasoning: "static page"}))
	got, err := repo.GetFindingByID(ctx, fp.ID)
	require.NoError(t, err)
	assert.Equal(t, "high", got.Severity, "false_positive must not downgrade severity")
	assert.Equal(t, database.StatusFalsePositive, got.Status)
	assert.Contains(t, got.Description, "static page")
	assert.Equal(t, triageStatusActor, got.StatusActor)

	ok := seedTriageFinding(t, repo, "medium")
	require.NoError(t, applyTriageVerdict(ctx, repo, database.DefaultProjectUUID, ok,
		&agent.TriageConfirmResult{Verdict: agent.TriageVerdictConfirmed, Reasoning: "reproduced"}))
	got, err = repo.GetFindingByID(ctx, ok.ID)
	require.NoError(t, err)
	assert.Equal(t, database.StatusConfirmed, got.Status)
	assert.Equal(t, "medium", got.Severity)

	unk := seedTriageFinding(t, repo, "low")
	before := unk.Status
	require.NoError(t, applyTriageVerdict(ctx, repo, database.DefaultProjectUUID, unk,
		&agent.TriageConfirmResult{Verdict: agent.TriageVerdictInconclusive, Reasoning: "target down"}))
	got, err = repo.GetFindingByID(ctx, unk.ID)
	require.NoError(t, err)
	assert.Equal(t, before, got.Status, "inconclusive writes nothing")
	assert.Equal(t, "orig", got.Description)
}

// TestApplyTriageVerdictNoWrite: --no-write reports the verdict and what it
// would set, and plans no write at all.
func TestApplyTriageVerdictNoWrite(t *testing.T) {
	f := &database.Finding{ID: 7, Severity: "high", Status: database.StatusDraft}
	v := &agent.TriageConfirmResult{Verdict: agent.TriageVerdictFalsePositive, Reasoning: "r"}

	out := planTriageWrite(f, v, true)
	assert.False(t, out.Written)
	assert.Equal(t, database.StatusDraft, out.NewStatus)
	assert.Equal(t, "high", out.NewSeverity)

	out = planTriageWrite(f, v, false)
	assert.True(t, out.Written)
	assert.Equal(t, database.StatusFalsePositive, out.NewStatus)
	assert.Equal(t, "high", out.OldSeverity)
	assert.Equal(t, "high", out.NewSeverity, "severity is never changed by triage")

	out = planTriageWrite(f, &agent.TriageConfirmResult{Verdict: agent.TriageVerdictInconclusive}, false)
	assert.False(t, out.Written, "inconclusive never writes")
}

// TestBashEnvBuilderPinsBinaryAndDB: the bash tool's children find this
// binary first on PATH and open this process's database — scoped (VIGOLIUM_DB
// + VIGOLIUM_PROJECT_UUID) for a scoped parent, never VIGOLIUM_DB_PATH, which
// would turn project scoping off for their reads.
func TestBashEnvBuilderPinsBinaryAndDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "acme.sqlite")
	prevDB, prevCfg, prevUnscoped, prevPinned := globalDB, globalConfig, agentChildDBUnscoped, dbPathEnvPinned
	prevOpened, prevDriver := clicommon.OpenedDBPath(), clicommon.OpenedDBDriver()
	prevProject := globalProjectUUID
	t.Cleanup(func() {
		globalDB, globalConfig, agentChildDBUnscoped, dbPathEnvPinned = prevDB, prevCfg, prevUnscoped, prevPinned
		clicommon.SetOpenedDBPath(prevOpened)
		clicommon.SetOpenedDBDriver(prevDriver)
		globalProjectUUID = prevProject
		clicommon.ResetProjectResolutionForTest()
	})
	const project = "0b7e9c1a-5d2f-4e3a-9c8b-7a6d5e4f3a2b"
	clicommon.ResetProjectResolutionForTest()
	globalProjectUUID = project
	globalDB = dbPath
	globalConfig = "/etc/vigolium/test.yaml"
	agentChildDBUnscoped, dbPathEnvPinned = false, false
	clicommon.SetOpenedDBPath(dbPath)
	clicommon.SetOpenedDBDriver("sqlite")
	t.Setenv(dbPathEnvVar, "/somewhere/else.sqlite")
	t.Setenv("PATH", "/usr/bin:/bin")

	env := envMap(agentChildEnv())
	exe, err := os.Executable()
	require.NoError(t, err)
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	assert.Equal(t, exe, env[binEnvVar])

	first := strings.Split(env["PATH"], string(os.PathListSeparator))[0]
	target, err := os.Readlink(filepath.Join(first, "vigolium"))
	if err == nil {
		assert.Equal(t, exe, target, "PATH's first entry links vigolium to this binary")
	} else {
		assert.Equal(t, filepath.Dir(exe), first)
	}
	assert.True(t, strings.HasSuffix(env["PATH"], "/usr/bin:/bin"), "the inherited PATH follows")

	assert.Equal(t, dbPath, env[dbEnvVar])
	_, hasPath := env[dbPathEnvVar]
	assert.False(t, hasPath, "a scoped parent must not hand children VIGOLIUM_DB_PATH")
	assert.Equal(t, project, env[projectUUIDEnv])
	assert.Equal(t, "/etc/vigolium/test.yaml", env[configEnvVar])

	// An unscoped parent (-S throwaway DB) keeps the unscoped pin.
	agentChildDBUnscoped = true
	env = envMap(agentChildEnv())
	assert.Equal(t, dbPath, env[dbPathEnvVar])
	_, hasDB := env[dbEnvVar]
	assert.False(t, hasDB)
	_, hasProject := env[projectUUIDEnv]
	assert.False(t, hasProject)
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// TestApplyDBEnvIsScopedDB: VIGOLIUM_DB is --db from the environment: it
// pins the database without turning project scoping off, and wins over
// VIGOLIUM_DB_PATH.
func TestApplyDBEnvIsScopedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "scoped.sqlite")
	prevDB, prevPinned, prevAuto := globalDB, dbPathEnvPinned, dbPathEnvAutoStateless
	t.Cleanup(func() { globalDB, dbPathEnvPinned, dbPathEnvAutoStateless = prevDB, prevPinned, prevAuto })
	globalDB, dbPathEnvPinned, dbPathEnvAutoStateless = "", false, false
	t.Setenv(dbEnvVar, dbPath)
	t.Setenv(dbPathEnvVar, filepath.Join(t.TempDir(), "other.sqlite"))

	require.NoError(t, applyDBPathEnv(agentQueryCmd))
	assert.Equal(t, dbPath, globalDB)
	assert.False(t, dbPathEnvPinned)
	assert.False(t, dbPathEnvAutoStateless, "VIGOLIUM_DB must not turn project scoping off")
}

// TestParseListModesNDJSON: --list-modes -j wraps audit's NDJSON as rows.
func TestParseListModesNDJSON(t *testing.T) {
	modes, err := parseListModesNDJSON([]byte("{\"name\":\"lite\"}\n\n{\"name\":\"deep\"}\n"))
	require.NoError(t, err)
	require.Len(t, modes, 2)
	assert.Equal(t, "deep", modes[1]["name"])
	_, err = parseListModesNDJSON([]byte("not json\n"))
	assert.Error(t, err)
}
