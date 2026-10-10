package integration_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	deparosresources "github.com/vigolium/vigolium/internal/resources/deparos"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
)

// jsPersistenceBundle makes four kinds of request the discovery crawl used to
// lose: a GET whose route 404s, a POST that replay_safety withholds, a
// templated path that 404s once its variable is filled in, and a route that
// answers 400 (not found to the Analyzer, but proof the route exists). It also declares a client route, a non-request fact that
// belongs in the asset's jstangle-facts artifact.
const jsPersistenceBundle = `
fetch("/api/v2/users").then(function (r) { return r.json(); });
fetch("/api/v2/items").then(function (r) { return r.json(); });
axios.post("/api/v2/orders", { sku: "a1", qty: 1 });
function summary(kind) { return fetch("/api/v2/" + kind + "/summary"); }
fetch("/api/v2/upload");
const routes = [{ path: "/admin/reports", component: Reports }];
`

// TestDiscoveryEndToEnd_JSPersistence runs real discovery (with the embedded
// jstangle helper) against a local server and checks that every JS-derived
// request reaches http_records under source=jstangle with jstangle:* remarks,
// that the withheld POST was never sent, and that the post-discovery deparos
// cleanup leaves the rows alone.
func TestDiscoveryEndToEnd_JSPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the jstangle helper; skipped in -short")
	}
	if len(deparosresources.JSTangleBinaryZst) <= 1024 {
		t.Skip("no valid embedded jstangle helper for this platform")
	}

	server := NewTestServer([]ResponseScenario{
		{Path: "/", StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"},
			Body: `<html><head><script src="/static/app.js"></script></head><body>app</body></html>`},
		{Path: "/static/app.js", StatusCode: 200, Headers: map[string]string{"Content-Type": "application/javascript"},
			Body: jsPersistenceBundle},
		{Path: "/api/v2/users", StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"},
			Body: `[{"id":1,"name":"a"}]`},
		{Path: "/api/v2/upload", StatusCode: 400, Headers: map[string]string{"Content-Type": "application/json"},
			Body: `{"error":"missing parameter: file"}`},
	})
	defer server.Close()

	ctx := context.Background()
	db, err := database.NewDB(&config.DatabaseConfig{Enabled: true, Driver: "sqlite", SQLite: config.SQLiteConfig{
		Path: filepath.Join(t.TempDir(), "js.sqlite"), BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL", CacheSize: 1000,
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(ctx))
	repo := database.NewRepository(db)

	src, err := source.NewDeparosDiscoverySource(ctx, source.DeparosDiscoveryConfig{
		Targets:      []string{server.URL()},
		Concurrency:  4,
		MaxDuration:  2 * time.Minute,
		DrainTimeout: 10 * time.Second,
		Repository:   repo,
		ProjectUUID:  database.DefaultProjectUUID,
	})
	require.NoError(t, err)

	var emitted []string
	deadline, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for {
		item, nextErr := src.Next(deadline)
		if errors.Is(nextErr, io.EOF) {
			break
		}
		require.NoError(t, nextErr)
		emitted = append(emitted, item.Request.Request().Method()+" "+item.Request.Request().Path())
	}
	require.NoError(t, src.Close())

	for _, r := range server.GetRequestsForPath("/api/v2/orders") {
		assert.NotEqual(t, "POST", r.Method, "replay_safety read-only: the withheld POST must never be sent")
	}

	// The same cleanup the runner applies after discovery.
	_, err = repo.ApplyDeparosStatusPolicy(ctx, database.DefaultProjectUUID, database.DeparosStatusPolicy{})
	require.NoError(t, err)
	_, err = repo.DeduplicateSoftDeparosRecords(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)

	var rows []database.HTTPRecord
	require.NoError(t, db.NewSelect().Model(&rows).Where("source = ?", "jstangle").Scan(ctx))
	remarks := map[string][]string{}
	for _, row := range rows {
		remarks[row.Method+" "+row.Path] = row.Remarks
	}
	t.Logf("jstangle rows: %v", remarks)

	require.Contains(t, remarks, "GET /api/v2/items", "a JS endpoint that 404s must be persisted")
	assert.Contains(t, remarks["GET /api/v2/items"], "jstangle:replayed_not_found")
	assert.Contains(t, remarks["GET /api/v2/items"], "jstangle:confidence=high")

	require.Contains(t, remarks, "POST /api/v2/orders", "a withheld POST must be persisted")
	assert.Contains(t, remarks["POST /api/v2/orders"], "jstangle:withheld_policy")
	assert.Contains(t, remarks["POST /api/v2/orders"], "jstangle:reason=method:POST")

	require.Contains(t, remarks, "GET /api/v2/upload")
	assert.Contains(t, remarks["GET /api/v2/upload"], "jstangle:replayed_not_found")
	require.Contains(t, remarks, "GET /api/v2/users")
	assert.Contains(t, remarks["GET /api/v2/users"], "jstangle:replayed_found")

	hasTemplated := false
	for key, r := range remarks {
		if slices.Contains(r, "jstangle:replayed_not_found") && key != "GET /api/v2/items" && key != "GET /api/v2/upload" {
			hasTemplated = true
		}
	}
	assert.True(t, hasTemplated, "the templated /api/v2/${kind}/summary replay must be persisted too")

	// Emission: the 400 stub goes to later phases; the 404 and the withheld POST do not.
	assert.Contains(t, emitted, "GET /api/v2/upload")
	assert.NotContains(t, emitted, "GET /api/v2/items")
	assert.NotContains(t, emitted, "POST /api/v2/orders")

	var kinds []struct {
		Kind  string `bun:"kind"`
		Count int    `bun:"n"`
	}
	require.NoError(t, db.NewRaw("SELECT kind, COUNT(*) AS n FROM analysis_artifacts GROUP BY kind").Scan(ctx, &kinds))
	counts := map[string]int{}
	for _, k := range kinds {
		counts[k.Kind] = k.Count
	}
	assert.GreaterOrEqual(t, counts["jstangle-fact"], 4, "every template record carries its fact")
	assert.GreaterOrEqual(t, counts["jstangle-facts"], 1, "the bundle's client route lands in a facts artifact")

	stats := src.Stats()
	assert.GreaterOrEqual(t, stats.JSFactsPersisted, 3)
	assert.GreaterOrEqual(t, stats.JSFactsNotFound, 2)
	assert.Positive(t, stats.JSFactsWithheld["withheld_policy"])
}
