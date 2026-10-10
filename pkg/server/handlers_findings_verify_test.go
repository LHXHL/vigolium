package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/verify"
)

const verifyTestScan = "scan-verify-1"

func verifyTestApp(t *testing.T, project string) (*fiber.App, *database.Repository) {
	t.Helper()
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{Version: "v-test"}, &fakeQueue{}, db, repo, nil)
	return verifyTestMount(h, project), repo
}

// verifyTestMount mounts the verify route with project as the request's
// resolved project ("" = default).
func verifyTestMount(h *Handlers, project string) *fiber.App {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		if project != "" {
			c.Locals(projectUUIDLocalsKey, project)
		}
		return c.Next()
	})
	app.Use(apiVersionMiddleware(apicontract.RESTAPIVersion1))
	app.Post("/api/findings/:id/verify", h.HandleVerifyFinding)
	return app
}

func verifyTestFinding(t *testing.T, repo *database.Repository, f *database.Finding) *database.Finding {
	t.Helper()
	f.ProjectUUID = database.DefaultProjectUUID
	f.ScanUUID = verifyTestScan
	f.Severity, f.Confidence = "high", "firm"
	require.NoError(t, repo.SaveFindingDirect(context.Background(), f))
	got, _, err := repo.ResolveFindings(context.Background(), database.DefaultProjectUUID, nil, []string{f.FindingHash})
	require.NoError(t, err)
	require.Len(t, got, 1)
	return got[0]
}

func verifyTestRecord(t *testing.T, repo *database.Repository, rr *httpmsg.HttpRequestResponse) string {
	t.Helper()
	uuid, err := repo.SaveRecordWithLineage(context.Background(), rr, "scanner", database.DefaultProjectUUID,
		database.RecordLineage{ScanUUID: verifyTestScan})
	require.NoError(t, err)
	return uuid
}

// A passive finding is re-analyzed on its stored record (nothing sent), the
// verdict is written, and the finding is addressable by hash prefix too.
func TestHandleVerifyFinding_Passive(t *testing.T) {
	app, repo := verifyTestApp(t, "")
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	rec := modtest.Request(t, srv.URL+"/item").WithResponse(httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\nbody")))
	f := verifyTestFinding(t, repo, &database.Finding{
		ModuleID: "software-version-header", ModuleName: "Software Version Disclosed in Headers",
		FindingHash: strings.Repeat("cd", 20), URL: srv.URL + "/item",
		HTTPRecordUUIDs: []string{verifyTestRecord(t, repo, rec)},
	})

	status, body := doReq(t, app, http.MethodPost, "/api/findings/"+strings.Repeat("cd", 6)+"/verify", "", nil)
	require.Equal(t, http.StatusOK, status, string(body))
	var res verify.Result
	require.NoError(t, json.Unmarshal(body, &res))
	assert.Equal(t, f.ID, res.ID)
	assert.Equal(t, database.VerdictConfirmed, res.Verdict, res.Reason)
	assert.True(t, res.Written)
	assert.Zero(t, hits.Load(), "a passive verify sends nothing")

	got, err := repo.GetFindingByID(context.Background(), f.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Verification)
	assert.Equal(t, database.VerdictConfirmed, got.Verification.Verdict)
	assert.Equal(t, "v-test", got.Verification.ModuleVersion)
}

// An active finding re-runs its module against the local target; mark moves
// the status, and the v2 body is the mutation list envelope.
func TestHandleVerifyFinding_ActiveMarkV2(t *testing.T) {
	app, repo := verifyTestApp(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'")\`) {
			_, _ = io.WriteString(w, "You have an error in your SQL syntax; check the manual that "+
				"corresponds to your MySQL server version for the right syntax near 'x' at line 1")
			return
		}
		_, _ = io.WriteString(w, "<html>normal page</html>")
	}))
	defer srv.Close()
	base := modtest.Request(t, srv.URL+"/item?id=1&q=x").WithResponse(httpmsg.NewHttpResponse(
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nitem page")))
	f := verifyTestFinding(t, repo, &database.Finding{
		ModuleID: "sqli-error-based", ModuleName: "SQL Injection (Error-Based)",
		FindingHash: strings.Repeat("ef", 20), URL: srv.URL + "/item?id=1&q=x",
		OriginRecordUUID: verifyTestRecord(t, repo, base),
		InsertionPoint:   &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
	})

	status, body := doReq(t, app, http.MethodPost, "/api/findings/"+strconv.FormatInt(f.ID, 10)+"/verify",
		`{"mark":true,"timeout":"1m"}`, map[string]string{apicontract.RESTAPIVersionHeader: "2"})
	require.Equal(t, http.StatusOK, status, string(body))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))
	assert.Equal(t, "mutation", doc["kind"])
	assert.Equal(t, true, doc["changed"])
	assert.Equal(t, true, doc["project_scoped"])
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	item := items[0].(map[string]any)
	assert.Equal(t, database.VerdictConfirmed, item["verdict"], item["reason"])
	assert.Positive(t, item["requests"])

	got, err := repo.GetFindingByID(context.Background(), f.ID)
	require.NoError(t, err)
	assert.Equal(t, database.StatusConfirmed, got.Status)
}

// dry_run returns the reconstruction and writes nothing; a finding in another
// project is 404; contradictory options are 400.
func TestHandleVerifyFinding_DryRunScopeAndValidation(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := verifyTestMount(h, "")
	rec := modtest.Request(t, "http://127.0.0.1:1/item").WithResponse(httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\nbody")))
	f := verifyTestFinding(t, repo, &database.Finding{
		ModuleID: "software-version-header", ModuleName: "Software Version Disclosed in Headers",
		FindingHash: strings.Repeat("aa", 20), URL: "http://127.0.0.1:1/item",
		HTTPRecordUUIDs: []string{verifyTestRecord(t, repo, rec)},
	})
	path := "/api/findings/" + strconv.FormatInt(f.ID, 10) + "/verify"

	status, body := doReq(t, app, http.MethodPost, path, `{"dry_run":true}`, nil)
	require.Equal(t, http.StatusOK, status, string(body))
	var res verify.Result
	require.NoError(t, json.Unmarshal(body, &res))
	assert.Empty(t, res.Verdict)
	assert.False(t, res.Written)
	require.NotNil(t, res.Plan)
	got, err := repo.GetFindingByID(context.Background(), f.ID)
	require.NoError(t, err)
	assert.Nil(t, got.Verification, "a dry run writes nothing")

	for _, bad := range []string{`{"mark":true,"dry_run":true}`, `{"mark":true,"no_write":true}`, `{"timeout":"soon"}`, `{"timeout":"1h"}`, `{"rate_limit":-1}`} {
		status, body = doReq(t, app, http.MethodPost, path, bad, nil)
		assert.Equal(t, http.StatusBadRequest, status, "%s: %s", bad, body)
	}

	status, body = doReq(t, app, http.MethodPost, "/api/findings/999999/verify", "", nil)
	assert.Equal(t, http.StatusNotFound, status, string(body))

	foreign := verifyTestMount(h, "11111111-2222-3333-4444-555555555555")
	status, body = doReq(t, foreign, http.MethodPost, path, "", nil)
	assert.Equal(t, http.StatusNotFound, status, string(body))
	assert.Contains(t, string(body), string(apicontract.CodeFindingNotFound))
}
