package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// directRowFixture points the direct path at a fresh temp store with one cheap
// passive module, and restores every global it touched.
func directRowFixture(t *testing.T) {
	t.Helper()
	orig := struct {
		db, scanUUID     string
		silent, json     bool
		modules, moduleT []string
	}{globalDB, globalScanUUID, globalSilent, globalJSON, globalModules, globalModuleTags}
	t.Cleanup(func() {
		globalDB, globalScanUUID, globalSilent, globalJSON = orig.db, orig.scanUUID, orig.silent, orig.json
		globalModules, globalModuleTags = orig.modules, orig.moduleT
		resetDBCacheForTest()
	})
	resetDBCacheForTest()
	// A throwaway HOME: each row's liveness heartbeat writes status.json under
	// the configured sessions dir (~/.vigolium/native-sessions by default).
	t.Setenv("HOME", t.TempDir())
	globalDB = filepath.Join(t.TempDir(), "direct.sqlite")
	globalScanUUID = ""
	globalSilent = true
	globalJSON = false
	// One passive module that always fires on a bare response: no security
	// headers. Keeps the run to a handful of requests against the local server.
	globalModules = []string{"security-headers-missing"}
	globalModuleTags = nil
}

func bareServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func directInput(t *testing.T, target string) scanInput {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(target)
	require.NoError(t, err)
	return scanInput{rr: rr, target: target, method: "GET"}
}

func scanRow(t *testing.T, uuid string) *database.Scan {
	t.Helper()
	db, err := getDB()
	require.NoError(t, err)
	row, err := database.NewRepository(db).GetScanByUUID(context.Background(), uuid)
	require.NoError(t, err, "scan row %s must exist", uuid)
	return row
}

// A direct scan-url run creates a completed scan row, stamps its findings and
// records with the row's UUID, and reports that UUID in the -j document.
func TestDirectScanCreatesScanRow(t *testing.T) {
	directRowFixture(t)
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")
	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})

	result, err := executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.ScanUUID, "the UUID is always minted")
	require.True(t, result.Persisted)

	row := scanRow(t, result.ScanUUID)
	assert.Equal(t, "scan-url", row.Name)
	assert.Equal(t, "single", row.ScanMode)
	assert.Equal(t, "cli", row.ScanSource)
	assert.Equal(t, in.target, row.Target)
	assert.Equal(t, "completed", row.Status)
	assert.Equal(t, database.CompletenessComplete, row.Completeness)
	assert.False(t, row.FinishedAt.IsZero())
	// The row carried a liveness heartbeat while the input ran.
	require.NotNil(t, row.HeartbeatAt, "the direct path heartbeats its row")
	assert.Equal(t, os.Getpid(), row.PID)

	db, err := getDB()
	require.NoError(t, err)
	ctx := context.Background()
	var findings []*database.Finding
	require.NoError(t, db.NewSelect().Model(&findings).Scan(ctx))
	require.NotEmpty(t, findings, "the passive module fires on a response with no security headers")
	for _, f := range findings {
		assert.Equal(t, result.ScanUUID, f.ScanUUID)
		// Regression: `finding -j` renders through compactFindingView, which
		// emits scan_uuid whenever the finding carries one. The direct path used
		// to leave it empty, so the key was simply missing.
		view := compactFindingView(f, nil, agentViewOptions{})
		assert.Equal(t, result.ScanUUID, view["scan_uuid"])
	}

	n, err := database.NewRepository(db).CountRecordsForScan(ctx, "", result.ScanUUID)
	require.NoError(t, err)
	assert.Positive(t, n, "records_written counts the records this scan stored")

	var logs []*database.ScanLog
	require.NoError(t, db.NewSelect().Model(&logs).Where("scan_uuid = ?", result.ScanUUID).Scan(ctx))
	assert.GreaterOrEqual(t, len(logs), 2, "`log <uuid>` shows at least the start and finish lines")

	builder := newScanDocBuilder("scan-url")
	builder.AddDirect(result, nil)
	doc, err := encodeAgentJSON(builder.envelope())
	require.NoError(t, err)
	var decoded struct {
		ScanUUID  string           `json:"scan_uuid"`
		Persisted bool             `json:"persisted"`
		Items     []map[string]any `json:"items"`
		Total     int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(doc, &decoded))
	assert.Equal(t, result.ScanUUID, decoded.ScanUUID, "the -j document names the row")
	assert.True(t, decoded.Persisted)
	assert.Positive(t, decoded.Total, "items are the stored rows of this scan")
	require.NotEmpty(t, decoded.Items)
	assert.NotNil(t, decoded.Items[0]["id"], "a persisted finding is read back with its store id")
	sess.close()

	// Once the session closes, status.json records the row's terminal status.
	st, err := runner.ReadSessionStatus(runner.SessionStatusPath(settingsOrDefaults().ScanningStrategy.ScanLogs.EffectiveSessionsDir(), result.ScanUUID))
	require.NoError(t, err)
	require.NotNil(t, st, "status.json is written under the (temp) sessions dir")
	assert.Equal(t, "completed", st.Status)
}

// A target nothing answers on fails its row with no_targets_reachable.
func TestDirectScanDeadTargetRow(t *testing.T) {
	directRowFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL + "/"
	srv.Close() // the port now refuses connections

	in := directInput(t, dead)
	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	result, err := executeDirectScan(context.Background(), sess, in.rr, in.target, in.method)
	require.NoError(t, err)

	row := scanRow(t, result.ScanUUID)
	assert.Equal(t, "failed", row.Status)
	assert.Equal(t, database.CompletenessPartial, row.Completeness)
	assert.Equal(t, database.ReasonNoTargetsReachable, row.StopReason)
	sess.close()
}

// An interrupted run still gets a finalized row, judged the way the runner
// judges one: failed "cancelled", partial, stop reason cancelled.
func TestDirectScanInterruptedRow(t *testing.T) {
	directRowFixture(t)
	srv := bareServer(t)
	in := directInput(t, srv.URL+"/")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{in})
	result, _ := executeDirectScan(ctx, sess, in.rr, in.target, in.method)
	require.NotNil(t, result)
	assert.True(t, result.Interrupted)

	row := scanRow(t, result.ScanUUID)
	assert.Equal(t, "failed", row.Status)
	assert.Equal(t, "cancelled", row.ErrorMessage)
	assert.Equal(t, database.CompletenessPartial, row.Completeness)
	assert.Equal(t, database.ReasonCancelled, row.StopReason)
	sess.close()
}

// Unpinned inputs get one row each; a pinned --scan-uuid shares one row whose
// target lists every input. The store stays open across inputs (it used to be
// closed after the first).
func TestDirectScanRowsPerInputAndPinned(t *testing.T) {
	directRowFixture(t)
	srv := bareServer(t)
	a, b := directInput(t, srv.URL+"/a"), directInput(t, srv.URL+"/b")

	sess := newDirectScanSession(database.ScanNameScanURL, []scanInput{a, b})
	ra, err := executeDirectScan(context.Background(), sess, a.rr, a.target, a.method)
	require.NoError(t, err)
	rb, err := executeDirectScan(context.Background(), sess, b.rr, b.target, b.method)
	require.NoError(t, err)
	assert.NotEqual(t, ra.ScanUUID, rb.ScanUUID, "unpinned inputs mint their own UUIDs")
	assert.Equal(t, a.target, scanRow(t, ra.ScanUUID).Target)
	assert.Equal(t, b.target, scanRow(t, rb.ScanUUID).Target)

	globalScanUUID = "11111111-2222-3333-4444-555555555555"
	pinned := newDirectScanSession(database.ScanNameScanURL, []scanInput{a, b})
	pa, err := executeDirectScan(context.Background(), pinned, a.rr, a.target, a.method)
	require.NoError(t, err)
	pb, err := executeDirectScan(context.Background(), pinned, b.rr, b.target, b.method)
	require.NoError(t, err)
	assert.Equal(t, globalScanUUID, pa.ScanUUID)
	assert.Equal(t, globalScanUUID, pb.ScanUUID)

	row := scanRow(t, globalScanUUID)
	assert.Equal(t, a.target+", "+b.target, row.Target)
	assert.Equal(t, "completed", row.Status)
	assert.Equal(t, database.CompletenessComplete, row.Completeness)

	db, err := getDB()
	require.NoError(t, err)
	n, err := db.NewSelect().Model((*database.Scan)(nil)).Where("uuid = ?", globalScanUUID).Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	pinned.close()
	sess.close()
}
