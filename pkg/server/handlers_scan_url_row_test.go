package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

// The REST single-request rows come from database.NewSingleRequestScan, the
// constructor the CLI direct path shares. This pins every field the handlers
// used to set inline, so the dedupe changed nothing a REST client reads.
//
// The admission semaphore is held full so the handler creates the row and then
// rejects the scan (503) without starting a background executor.
func TestSingleRequestScanRowsUseSharedConstructor(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	for i := 0; i < cap(h.nativeScanSem); i++ {
		h.nativeScanSem <- struct{}{}
	}
	t.Cleanup(func() {
		for len(h.nativeScanSem) > 0 {
			<-h.nativeScanSem
		}
	})

	app := fiber.New()
	app.Post("/api/scan-url", h.HandleScanURL)
	app.Post("/api/scan-request", h.HandleScanRequest)

	rawReq := base64.StdEncoding.EncodeToString([]byte("GET /x HTTP/1.1\r\nHost: b.example.test\r\n\r\n"))
	cases := []struct {
		path, body, name, target string
	}{
		{"/api/scan-url", `{"url":"http://a.example.test/p","modules":"xss"}`, "scan-url", "http://a.example.test/p"},
		{"/api/scan-request", `{"http_request_base64":"` + rawReq + `","target_url":"http://b.example.test/x","modules":"sqli"}`, "scan-request", "http://b.example.test/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doReq(t, app, http.MethodPost, tc.path, tc.body, nil)
			require.Equal(t, http.StatusServiceUnavailable, status, string(body))

			var rows []*database.Scan
			require.NoError(t, db.NewSelect().Model(&rows).Where("name = ?", tc.name).Scan(context.Background()))
			require.Len(t, rows, 1)
			row := rows[0]
			assert.Equal(t, database.DefaultProjectUUID, row.ProjectUUID)
			assert.Equal(t, tc.target, row.Target)
			assert.Equal(t, "single", row.ScanMode)
			assert.Equal(t, "api", row.ScanSource)
			assert.NotEmpty(t, row.Modules)
			assert.False(t, row.StartedAt.IsZero())
			assert.Equal(t, "failed", row.Status, "a rejected scan is finalized, not left running")
		})
	}
}

// The background scan finalizes its row with a coverage verdict instead of the
// completeness-less CompleteScan.
func TestCompleteSingleRequestScanWritesVerdict(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	ctx := context.Background()

	row := database.NewSingleRequestScan("rest-1", database.DefaultProjectUUID, database.ScanNameScanURL, "http://127.0.0.1:1/", "", "api")
	require.NoError(t, repo.CreateScan(ctx, row))

	tally := database.TargetTally{Requested: 1, Admitted: 1}
	h.completeSingleRequestScan("rest-1", nil,
		runner.DirectScanCompletion(core.ExecutionReport{}, false, false, nil, tally))

	got, err := repo.GetScanByUUID(ctx, "rest-1")
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
	assert.Equal(t, database.CompletenessPartial, got.Completeness)
	assert.Equal(t, database.ReasonNoTargetsReachable, got.StopReason)
	phases, err := json.Marshal(got.PhaseOutcomes)
	require.NoError(t, err)
	assert.Contains(t, string(phases), `"preflight"`)

	require.NoError(t, repo.CreateScan(ctx, database.NewSingleRequestScan("rest-2", database.DefaultProjectUUID, database.ScanNameScanRequest, "http://a/", "", "api")))
	boom := errors.New("boom")
	h.completeSingleRequestScan("rest-2", boom,
		runner.DirectScanCompletion(core.ExecutionReport{Responded: 1}, true, false, boom, database.TargetTally{}))
	got, err = repo.GetScanByUUID(ctx, "rest-2")
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
	assert.Equal(t, "boom", got.ErrorMessage)
	assert.Equal(t, database.ReasonError, got.StopReason)
}
