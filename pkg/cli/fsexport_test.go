package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fsexport"
)

// gzipBytes returns s gzip-compressed, for seeding a wire-encoded response body.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestWriteFSExport drives the full fs writer over a seeded DB and asserts the
// on-disk tree shape, the @target line, the gzip-decoded body, the index.json
// schema, and the finding→traffic cross-link.
func TestWriteFSExport(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)

	// alpha: https record with a gzip-encoded body + a linked High finding.
	gzBody := gzipBytes(t, "<html>HELLO-DECODED</html>")
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:                "rec-alpha",
		Scheme:              "https",
		Hostname:            "alpha.example",
		Port:                443,
		Method:              "GET",
		Path:                "/alpha",
		URL:                 "https://alpha.example/alpha",
		HTTPVersion:         "HTTP/1.1",
		RequestHash:         "rhash-alpha",
		StatusCode:          200,
		ResponseContentType: "text/html; charset=utf-8",
		HasResponse:         true,
		RawRequest:          []byte("GET /alpha HTTP/1.1\r\nHost: alpha.example\r\n\r\n"),
		RawResponse: append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n"),
			gzBody...),
	}).Exec(ctx)
	require.NoError(t, err)

	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		HTTPRecordUUIDs: []string{"rec-alpha"},
		ModuleID:        "broken-auth",
		ModuleName:      "Broken Authentication",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-alpha",
		URL:             "https://alpha.example/alpha",
		Hostname:        "alpha.example",
		Description:     "Auth bypass.",
		MatchedAt:       []string{"https://alpha.example/alpha"},
	}))

	// bravo: a second host with no finding, to assert finding:null + host count.
	_, err = db.NewInsert().Model(&database.HTTPRecord{
		UUID:        "rec-bravo",
		Scheme:      "http",
		Hostname:    "bravo.example",
		Port:        80,
		Method:      "POST",
		Path:        "/login",
		URL:         "http://bravo.example/login",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-bravo",
		StatusCode:  403,
		HasResponse: true,
		RawRequest:  []byte("POST /login HTTP/1.1\r\nHost: bravo.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{}"),
	}).Exec(ctx)
	require.NoError(t, err)

	base := filepath.Join(t.TempDir(), "out")
	stats, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, stats.Traffic)
	assert.Equal(t, 1, stats.Findings)
	assert.Equal(t, 2, stats.Hosts)

	trafficRoot := base + "-traffic"
	findingsRoot := base + "-findings"

	// .req carries the @target authority line then the raw request verbatim.
	reqData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.req"))
	require.NoError(t, err)
	req := string(reqData)
	assert.True(t, strings.HasPrefix(req, "@target https://alpha.example\nGET /alpha HTTP/1.1\r\n"),
		"req must lead with @target then the raw request: %q", req)

	// .resp.headers keeps the status line + headers, no body.
	hdrData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.resp.headers"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(hdrData), "HTTP/1.1 200 OK\r\n"))

	// .resp.body is gzip-decoded so it greps as plaintext.
	bodyData, err := os.ReadFile(filepath.Join(trafficRoot, "alpha.example", "0001.resp.body"))
	require.NoError(t, err)
	assert.Equal(t, "<html>HELLO-DECODED</html>", string(bodyData))

	// traffic index.json schema + per-record finding severity backfill.
	var traffic []map[string]any
	readJSON(t, filepath.Join(trafficRoot, "index.json"), &traffic)
	require.Len(t, traffic, 2)
	byHost := map[string]map[string]any{}
	for _, e := range traffic {
		byHost[e["host"].(string)] = e
	}
	alpha := byHost["alpha.example"]
	assert.Equal(t, "0001", alpha["id"])
	assert.Equal(t, "alpha.example/0001", alpha["path"])
	assert.Equal(t, "GET", alpha["method"])
	assert.Equal(t, "/alpha", alpha["url"])
	assert.EqualValues(t, 200, alpha["status"])
	assert.Equal(t, "text/html", alpha["content_type"])
	assert.Equal(t, "high", alpha["finding"], "linked record must carry its finding's severity")
	assert.Nil(t, byHost["bravo.example"]["finding"], "unlinked record must have finding:null")

	// finding markdown cross-links back to the exact .req file AND embeds the
	// linked record's request/response inline (gzip body decoded) so the finding
	// is self-contained and shareable on its own.
	mdData, err := os.ReadFile(filepath.Join(findingsRoot, "alpha.example", "0001.md"))
	require.NoError(t, err)
	md := string(mdData)
	assert.Contains(t, md, "# HIGH — Broken Authentication")
	assert.Contains(t, md, "../../out-traffic/alpha.example/0001.req")
	assert.Contains(t, md, "## Request")
	assert.Contains(t, md, "GET /alpha HTTP/1.1", "raw request must be embedded inline")
	assert.NotContains(t, md, "@target", "the synthetic @target marker line must be stripped from the inline request")
	assert.Contains(t, md, "## Response")
	assert.Contains(t, md, "<html>HELLO-DECODED</html>", "decoded response body must be embedded inline")

	// findings index.json links to the traffic path.
	var findings []map[string]any
	readJSON(t, filepath.Join(findingsRoot, "index.json"), &findings)
	require.Len(t, findings, 1)
	assert.Equal(t, "alpha.example/0001.md", findings[0]["path"])
	assert.Equal(t, "high", findings[0]["severity"])
	assert.Equal(t, "broken-auth", findings[0]["module"])
	tr, _ := findings[0]["traffic"].([]any)
	require.Len(t, tr, 1)
	assert.Equal(t, "alpha.example/0001", tr[0])
}

// An identity selector has to narrow both halves of the tree. `db export --uuid
// <rec> --format fs` used to write the one selected .req beside EVERY finding in
// the store, producing a directory that reads as "the findings for this request"
// and is not.
func TestWriteFSExportUUIDBoundsFindings(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	for _, host := range []string{"alpha", "bravo"} {
		_, err := db.NewInsert().Model(&database.HTTPRecord{
			UUID:        "rec-" + host,
			Scheme:      "https",
			Hostname:    host + ".example",
			Port:        443,
			Method:      "GET",
			Path:        "/" + host,
			URL:         "https://" + host + ".example/" + host,
			HTTPVersion: "HTTP/1.1",
			RequestHash: "rhash-" + host,
			StatusCode:  200,
			HasResponse: true,
			RawRequest:  []byte("GET /" + host + " HTTP/1.1\r\nHost: " + host + ".example\r\n\r\n"),
			RawResponse: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"),
		}).Exec(ctx)
		require.NoError(t, err)

		require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
			HTTPRecordUUIDs: []string{"rec-" + host},
			ModuleID:        "mod-" + host,
			ModuleName:      "Module " + host,
			ModuleType:      "active",
			Severity:        "high",
			Confidence:      "firm",
			FindingHash:     "hash-" + host,
			URL:             "https://" + host + ".example/" + host,
			Hostname:        host + ".example",
			Description:     "Finding on " + host,
			MatchedAt:       []string{"https://" + host + ".example/" + host},
		}))
	}

	base := filepath.Join(t.TempDir(), "out")
	stats, err := writeFSExport(ctx, db,
		database.QueryFilters{RecordUUIDs: []string{"rec-alpha"}}, base, fsExportOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, stats.Traffic, "only the selected record")
	assert.Equal(t, 1, stats.Findings, "only the findings linked to the selected record")

	var findings []map[string]any
	readJSON(t, filepath.Join(base+"-findings", "index.json"), &findings)
	require.Len(t, findings, 1)
	assert.Equal(t, "mod-alpha", findings[0]["module"])

	// bravo's finding must not have been written anywhere in the tree.
	_, err = os.Stat(filepath.Join(base+"-findings", "bravo.example"))
	assert.True(t, os.IsNotExist(err), "an unlinked finding's host dir must not be created")
}

// TestWriteFSExportOmitResponse drops the .resp.* files but keeps .req + index.
func TestWriteFSExportOmitResponse(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")

	base := filepath.Join(t.TempDir(), "out")
	_, err := writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{omitResponse: true})
	require.NoError(t, err)

	dir := filepath.Join(base+"-traffic", "alpha.example")
	_, err = os.Stat(filepath.Join(dir, "0001.req"))
	require.NoError(t, err, ".req must still be written")
	_, err = os.Stat(filepath.Join(dir, "0001.resp.body"))
	assert.True(t, os.IsNotExist(err), ".resp.body must be omitted")
	_, err = os.Stat(filepath.Join(dir, "0001.resp.headers"))
	assert.True(t, os.IsNotExist(err), ".resp.headers must be omitted")
}

func TestFSTargetLine(t *testing.T) {
	cases := []struct {
		scheme string
		host   string
		port   int
		want   string
	}{
		{"https", "a.example", 443, "@target https://a.example"},
		{"http", "a.example", 80, "@target http://a.example"},
		{"https", "a.example", 8443, "@target https://a.example:8443"},
		{"http", "a.example", 8080, "@target http://a.example:8080"},
		{"", "a.example", 0, "@target http://a.example"},
	}
	for _, c := range cases {
		got := fsexport.TargetLine(&database.HTTPRecord{Scheme: c.scheme, Hostname: c.host, Port: c.port})
		assert.Equal(t, c.want, got)
	}
}

// readJSON decodes a JSON file into v, failing the test on any error.
func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}
