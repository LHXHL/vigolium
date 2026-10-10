package verify

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const (
	testScan     = "scan-0001"
	sqliModule   = "sqli-error-based"
	mysqlErrText = "You have an error in your SQL syntax; check the manual that " +
		"corresponds to your MySQL server version for the right syntax near 'x' at line 1"
)

func newRepo(t *testing.T) *database.Repository {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_busy_timeout=5000")
	require.NoError(t, err)
	sqldb.SetMaxOpenConns(1)
	db := database.NewDBFromBun(bun.NewDB(sqldb, sqlitedialect.New()), "sqlite")
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

func saveRecord(t *testing.T, repo *database.Repository, rr *httpmsg.HttpRequestResponse, source string) string {
	t.Helper()
	uuid, err := repo.SaveRecordWithLineage(context.Background(), rr, source, database.DefaultProjectUUID,
		database.RecordLineage{ScanUUID: testScan})
	require.NoError(t, err)
	return uuid
}

func saveFinding(t *testing.T, repo *database.Repository, f *database.Finding) *database.Finding {
	t.Helper()
	f.ProjectUUID = database.DefaultProjectUUID
	f.ScanUUID = testScan
	if f.FindingHash == "" {
		f.FindingHash = strings.Repeat("ab", 20)
	}
	if f.Severity == "" {
		f.Severity, f.Confidence = "high", "firm"
	}
	require.NoError(t, repo.SaveFindingDirect(context.Background(), f))
	got, _, err := repo.ResolveFindings(context.Background(), database.DefaultProjectUUID, nil, []string{f.FindingHash})
	require.NoError(t, err)
	require.Len(t, got, 1)
	return got[0]
}

// sqliServer answers a quote in ?id with a MySQL error until fixed is set.
func sqliServer(t *testing.T, fixed *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if !fixed.Load() && strings.ContainsAny(r.URL.Query().Get("id"), `'")\`) {
			_, _ = io.WriteString(w, mysqlErrText)
			return
		}
		_, _ = io.WriteString(w, "<html>normal page, id looked fine</html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// withResponse attaches a stored 200 response, as a scanned record has.
func withResponse(rr *httpmsg.HttpRequestResponse, body string) *httpmsg.HttpRequestResponse {
	return rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body)))
}

func payloadRequest(t *testing.T, rr *httpmsg.HttpRequestResponse, name, payload string) string {
	t.Helper()
	return string(modtest.InsertionPoint(t, rr, name).BuildRequest([]byte(payload)))
}

func TestReconstruct(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	base := withResponse(modtest.Request(t, "http://app.test/item?id=1&q=x"), "item page")
	baseUUID := saveRecord(t, repo, base, "scanner")
	payload := payloadRequest(t, base, "id", "1'")
	evidence, err := httpmsg.ParseRawRequestWithURL(payload, "http://app.test/item?id=1%27&q=x")
	require.NoError(t, err)
	evidenceUUID := saveRecord(t, repo, withResponse(evidence, mysqlErrText), database.RecordKindFinding)

	t.Run("replay columns", func(t *testing.T) {
		f := saveFinding(t, repo, &database.Finding{
			ModuleID: sqliModule, ModuleName: "SQLi", FindingHash: strings.Repeat("01", 20),
			URL: "http://app.test/item?id=1&q=x", Request: payload, HTTPRecordUUIDs: []string{evidenceUUID},
			OriginRecordUUID: baseUUID, InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"}, Payload: "1'",
		})
		p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
		require.Empty(t, p.Verdict, p.Reason)
		assert.Equal(t, BaselineOriginRecord, p.Baseline.Source)
		assert.Equal(t, baseUUID, p.Baseline.RecordUUID)
		assert.Equal(t, PointStored, p.InsertionPointSource)
		assert.Equal(t, "id", p.InsertionPoint.Name)
		assert.Equal(t, "1'", p.Payload)
	})

	t.Run("legacy: linked record is the baseline", func(t *testing.T) {
		f := saveFinding(t, repo, &database.Finding{
			ModuleID: sqliModule, ModuleName: "SQLi", FindingHash: strings.Repeat("02", 20),
			URL: "http://app.test/item?id=1&q=x", Request: payload, HTTPRecordUUIDs: []string{baseUUID},
		})
		p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
		require.Empty(t, p.Verdict, p.Reason)
		assert.Equal(t, BaselineLinkedRecord, p.Baseline.Source)
		assert.Equal(t, baseUUID, p.Baseline.RecordUUID)
		require.NotNil(t, p.InsertionPoint)
		assert.Equal(t, PointDiffering, p.InsertionPointSource)
		assert.Equal(t, database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"}, *p.InsertionPoint)
	})

	t.Run("legacy: linked record is the evidence", func(t *testing.T) {
		f := saveFinding(t, repo, &database.Finding{
			ModuleID: sqliModule, ModuleName: "SQLi", FindingHash: strings.Repeat("03", 20),
			URL: "http://app.test/item?id=1%27&q=x", Request: payload, HTTPRecordUUIDs: []string{evidenceUUID},
		})
		p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
		require.Empty(t, p.Verdict, p.Reason)
		assert.Equal(t, BaselineMatchedRecord, p.Baseline.Source)
		assert.Equal(t, baseUUID, p.Baseline.RecordUUID)
		require.NotNil(t, p.InsertionPoint)
		assert.Equal(t, "id", p.InsertionPoint.Name)
		assert.Equal(t, PointDiffering, p.InsertionPointSource)
	})

	t.Run("legacy: no baseline", func(t *testing.T) {
		other := withResponse(modtest.Request(t, "http://other.test/x?id=1%27"), mysqlErrText)
		otherUUID := saveRecord(t, repo, other, database.RecordKindFinding)
		f := saveFinding(t, repo, &database.Finding{
			ModuleID: sqliModule, ModuleName: "SQLi", FindingHash: strings.Repeat("04", 20),
			URL: "http://other.test/x?id=1%27", Request: string(other.Request().Raw()), HTTPRecordUUIDs: []string{otherUUID},
		})
		p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
		assert.Equal(t, database.VerdictInconclusive, p.Verdict)
		assert.Contains(t, p.Reason, "no baseline")
	})

	t.Run("unsupported", func(t *testing.T) {
		oast := &database.Finding{ID: 1, ModuleID: "oast-interaction", FindingSource: database.FindingSourceOAST}
		assert.Equal(t, database.VerdictUnsupported, Reconstruct(ctx, repo, "", oast, nil).Verdict)
		ext := &database.Finding{ID: 2, ModuleID: "ext-not-loaded"}
		p := Reconstruct(ctx, repo, "", ext, nil)
		assert.Equal(t, database.VerdictUnsupported, p.Verdict)
		assert.Contains(t, p.Reason, "--ext")
	})
}

// TestRun_SQLiConfirmedThenNotReproduced: a real module against a local
// server reproduces the finding, and stops reproducing it once fixed.
func TestRun_SQLiConfirmedThenNotReproduced(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	var fixed atomic.Bool
	srv := sqliServer(t, &fixed, nil)

	base := withResponse(modtest.Request(t, srv.URL+"/item?id=1&q=x"), "item page")
	baseUUID := saveRecord(t, repo, base, "scanner")
	f := saveFinding(t, repo, &database.Finding{
		ModuleID: sqliModule, ModuleName: "SQL Injection (Error-Based)", URL: srv.URL + "/item?id=1&q=x",
		Request: payloadRequest(t, base, "id", "1'"), OriginRecordUUID: baseUUID,
		InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
	})

	opts := RunOptions{Requester: modtest.Requester(t)}
	res := Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), opts)
	require.Equal(t, database.VerdictConfirmed, res.Verdict, res.Reason)
	assert.Positive(t, res.Matched)
	assert.True(t, res.Plan.Network)

	fixed.Store(true)
	res = Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), opts)
	assert.Equal(t, database.VerdictNotReproduced, res.Verdict, res.Reason)
	assert.Zero(t, res.Matched)
}

// TestRun_InsertionPointFilter: only the stored point is tested — a finding
// on q is not confirmed by the id parameter's error.
func TestRun_InsertionPointFilter(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	var fixed atomic.Bool
	srv := sqliServer(t, &fixed, nil)
	base := withResponse(modtest.Request(t, srv.URL+"/item?id=1&q=x"), "item page")
	baseUUID := saveRecord(t, repo, base, "scanner")
	f := saveFinding(t, repo, &database.Finding{
		ModuleID: sqliModule, ModuleName: "SQL Injection (Error-Based)", URL: srv.URL + "/item?id=1&q=x",
		OriginRecordUUID: baseUUID, InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "q"},
	})
	res := Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), RunOptions{Requester: modtest.Requester(t)})
	assert.Equal(t, database.VerdictNotReproduced, res.Verdict, res.Reason)
}

func TestRun_UnreachableIsInconclusive(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there now

	base := withResponse(modtest.Request(t, url+"/item?id=1"), "item page")
	baseUUID := saveRecord(t, repo, base, "scanner")
	f := saveFinding(t, repo, &database.Finding{
		ModuleID: sqliModule, ModuleName: "SQLi", URL: url + "/item?id=1", OriginRecordUUID: baseUUID,
		InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
	})
	res := Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), RunOptions{Requester: modtest.Requester(t)})
	assert.Equal(t, database.VerdictInconclusive, res.Verdict, res.Reason)
}

// TestRun_PassiveUsesStoredRecord: a passive verify re-analyzes the stored
// record and sends nothing; --refetch analyzes a fresh response instead.
func TestRun_PassiveUsesStoredRecord(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok") // no version header any more
	}))
	defer srv.Close()

	rec := modtest.Request(t, srv.URL+"/item").WithResponse(httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\nbody")))
	recUUID := saveRecord(t, repo, rec, "scanner")
	f := saveFinding(t, repo, &database.Finding{
		ModuleID: "software-version-header", ModuleName: "Software Version Disclosed in Headers",
		URL: srv.URL + "/item", HTTPRecordUUIDs: []string{recUUID},
	})

	res := Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), RunOptions{})
	assert.Equal(t, database.VerdictConfirmed, res.Verdict, res.Reason)
	assert.False(t, res.Plan.Network)
	assert.Equal(t, database.ModuleTypePassive, res.Plan.ModuleType)
	assert.Zero(t, hits.Load(), "a passive verify must not send a request")

	res = Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil), RunOptions{Refetch: true, Requester: modtest.Requester(t)})
	assert.Equal(t, database.VerdictNotReproduced, res.Verdict, res.Reason)
	assert.Equal(t, int64(1), hits.Load(), "--refetch fetches the record once")
}

// TestRun_ExtensionModule: an ext-* finding verifies through a module loaded
// from an extension file.
func TestRun_ExtensionModule(t *testing.T) {
	ctx := context.Background()
	repo := newRepo(t)
	var fixed atomic.Bool
	srv := sqliServer(t, &fixed, nil)

	dir := t.TempDir()
	script := filepath.Join(dir, "sqli_probe.js")
	require.NoError(t, os.WriteFile(script, []byte(`module.exports = {
  id: "sqli-probe",
  name: "SQLi probe",
  severity: "high",
  confidence: "firm",
  type: "active",
  scanTypes: ["per_insertion_point"],
  scanPerInsertionPoint: function(ctx, insertion) {
    var resp = vigolium.http.send(insertion.buildRequest("1'"));
    if (resp && resp.body && resp.body.indexOf("SQL syntax") >= 0) {
      return [{ name: "SQLi probe", severity: "high", url: ctx.request.url }];
    }
    return null;
  }
};
`), 0o600))
	cfg := config.ExtensionsConfig{Enabled: true, CustomDir: []string{script}}
	requester := modtest.Requester(t)
	engine, err := jsext.NewEngine(&cfg, requester, &jsext.EngineOptions{})
	require.NoError(t, err)
	var mod modules.Module
	for _, m := range engine.ActiveModules() {
		if strings.HasPrefix(m.ID(), "ext-") {
			mod = m
		}
	}
	if mod == nil {
		t.Fatal("the extension did not load")
	}
	resolve := func(id string) modules.Module {
		if id == mod.ID() {
			return mod
		}
		return nil
	}

	base := withResponse(modtest.Request(t, srv.URL+"/item?id=1"), "item page")
	baseUUID := saveRecord(t, repo, base, "scanner")
	f := saveFinding(t, repo, &database.Finding{
		ModuleID: mod.ID(), ModuleName: "SQLi probe", URL: srv.URL + "/item?id=1", OriginRecordUUID: baseUUID,
		FindingSource:  database.FindingSourceExtension,
		InsertionPoint: &database.FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
	})
	res := Run(ctx, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, resolve), RunOptions{Requester: requester})
	assert.Equal(t, database.VerdictConfirmed, res.Verdict, res.Reason)

	// Without the extension loaded the same finding is unsupported.
	assert.Equal(t, database.VerdictUnsupported, Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil).Verdict)
}

func TestSingleDifferingPoint(t *testing.T) {
	base := []byte("POST /a?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nu=1&v=2")
	oneBody := []byte("POST /a?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\nu=1'--&v=2")
	two := []byte("POST /a?x=2 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\nu=1'--&v=2")
	added := []byte("POST /a?x=1 HTTP/1.1\r\nHost: h\r\nX-Forwarded-Host: evil\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nu=1&v=2")

	ip := singleDifferingPoint(base, oneBody)
	require.NotNil(t, ip, "a body change with its Content-Length is one point")
	assert.Equal(t, "u", ip.Name())
	assert.Nil(t, singleDifferingPoint(base, two), "two changed points are ambiguous")
	ip = singleDifferingPoint(base, added)
	require.NotNil(t, ip, "an injected header is the point it was injected at")
	assert.Equal(t, "X-Forwarded-Host", ip.Name())
	assert.Nil(t, singleDifferingPoint(base, base))
}
