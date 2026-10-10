package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// resetCompactFlags restores the package-level compact flags between cases.
func resetCompactFlags(t *testing.T) {
	t.Helper()
	set := func() {
		compactBodyOver, compactKeepHead = "64k", "4k"
		compactSkipContentTypes, compactOnlyContentTypes = nil, nil
		compactSkipPaths, compactOnlyPaths = nil, nil
		compactOlderThan, compactMaxDBSize = "", ""
		compactAllProjects, compactDryRun, compactNoVacuum = false, false, false
	}
	set()
	t.Cleanup(set)
}

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{
		"0":      0,
		"4096":   4096,
		"64k":    64 << 10,
		"64KB":   64 << 10,
		"64KiB":  64 << 10,
		"2048m":  2048 << 20,
		"2g":     2 << 30,
		" 12 b ": 12,
	}
	for in, want := range cases {
		got, err := parseByteSize(in)
		require.NoErrorf(t, err, "parseByteSize(%q)", in)
		require.Equalf(t, want, got, "parseByteSize(%q)", in)
	}
	for _, in := range []string{"", "k", "-1", "1.5m", "10x", "99999999999999999999g"} {
		_, err := parseByteSize(in)
		require.Errorf(t, err, "parseByteSize(%q) must fail", in)
	}
}

func TestResolveCompactOptions(t *testing.T) {
	resetCompactFlags(t)
	opts, err := resolveCompactOptions("proj")
	require.NoError(t, err)
	require.Equal(t, int64(65536), opts.BodyOver, "default --body-over is 64 KiB")
	require.Equal(t, int64(4096), opts.KeepHead, "default --keep-head is 4 KiB")
	require.True(t, opts.Vacuum)
	require.Equal(t, "proj", opts.ProjectUUID)
	require.Nil(t, opts.OlderThan)
	require.Zero(t, opts.MaxDBSize)

	compactOlderThan = "30d"
	compactMaxDBSize = "2048m"
	compactNoVacuum = true
	compactSkipContentTypes = []string{"*javascript*"}
	opts, err = resolveCompactOptions("")
	require.NoError(t, err)
	require.NotNil(t, opts.OlderThan)
	require.WithinDuration(t, time.Now().Add(-30*24*time.Hour), *opts.OlderThan, time.Minute)
	require.Equal(t, int64(2048<<20), opts.MaxDBSize)
	require.False(t, opts.Vacuum)
	require.Equal(t, []string{"*javascript*"}, opts.SkipContentTypes)

	// Every rejection is a usage error (exit 2), and happens before any open.
	for _, mutate := range []func(){
		func() { compactKeepHead = "64k" },
		func() { compactBodyOver = "lots" },
		func() { compactMaxDBSize = "0" },
		func() { compactOlderThan = "someday" },
	} {
		resetCompactFlags(t)
		mutate()
		_, err := resolveCompactOptions("")
		require.Error(t, err)
		require.Equal(t, ExitUsageError, classifyExitCode(err), "%v", err)
	}
}

// seedCompactDB writes a small file store with one large image response and one
// script, through the real write path.
func seedCompactDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "traffic.sqlite")
	db, err := database.NewDB(&config.DatabaseConfig{
		Enabled: true, Driver: "sqlite",
		SQLite: config.SQLiteConfig{Path: path, BusyTimeout: 5000, JournalMode: "WAL", Synchronous: "NORMAL"},
	})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, db.CreateSchema(ctx))
	require.NoError(t, db.SeedDefaults(ctx))
	repo := database.NewRepository(db)
	for _, f := range []struct{ path, ct string }{
		{"/hero.png", "image/png"},
		{"/app.js", "application/javascript"},
	} {
		rr, err := httpmsg.ParseRawRequest(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: t.example.com\r\n\r\n", f.path))
		require.NoError(t, err)
		body := strings.Repeat("z", 200<<10)
		rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte(
			"HTTP/1.1 200 OK\r\nContent-Type: " + f.ct + "\r\n\r\n" + body)))
		_, err = repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	return path
}

// The machine contract gimorra reads: one -j document, `items` carrying the
// summary, and the skip globs honored.
func TestRunDBCompactJSONContract(t *testing.T) {
	withMachineDocumentState(t)
	resetCompactFlags(t)
	t.Setenv("HOME", t.TempDir())
	globalDB = seedCompactDB(t)
	globalJSON = true
	compactAllProjects = true
	compactSkipContentTypes = []string{"*javascript*"}

	// Without --force a non-interactive pass is refused before anything opens.
	prevForce := globalForce
	t.Cleanup(func() { globalForce = prevForce })
	globalForce = false
	refused := runDBCompact(dbCompactCmd, nil)
	require.Error(t, refused)
	require.Equal(t, ExitUsageError, classifyExitCode(refused))
	globalForce = true

	var runErr error
	out := captureStdout(t, func() { runErr = runDBCompact(dbCompactCmd, nil) })
	require.NoError(t, runErr)

	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	require.Equal(t, "db compact", docs[0]["command"])
	require.Equal(t, "mutation", docs[0]["kind"])
	require.Equal(t, true, docs[0]["changed"])
	require.Equal(t, "compact", docs[0]["action"])
	rows, ok := docs[0]["items"].([]any)
	require.True(t, ok && len(rows) == 1, "items must be a one-element array holding the summary: %v", docs[0])
	items, ok := rows[0].(map[string]any)
	require.True(t, ok, "items[0] must be the summary object: %v", docs[0])
	for _, key := range []string{
		"dry_run", "records_compacted", "response_bodies_compacted", "request_bodies_compacted",
		"body_bytes_before", "body_bytes_after", "db_bytes_before", "db_bytes_after",
		"max_db_size", "budget_met", "remaining", "vacuumed",
	} {
		require.Contains(t, items, key)
	}
	require.EqualValues(t, 1, items["records_compacted"], "the script is protected by --skip-content-type")
	require.EqualValues(t, 200<<10, items["body_bytes_before"])
	require.EqualValues(t, 4<<10, items["body_bytes_after"])
	require.Equal(t, true, items["budget_met"])
	require.Equal(t, true, items["vacuumed"])
}

// A reader of `traffic -j` is told a body is a head, and what the whole was.
func TestTrafficViewCarriesBodyCompaction(t *testing.T) {
	marker := &database.BodyCompaction{Version: 1, KeepHead: 4096,
		Response: &database.CompactedBody{OriginalLength: 300000, SHA256: "ab", KeptLength: 4096}}
	m := compactRecordView(&database.HTTPRecord{UUID: "u", BodyCompaction: marker}, agentViewOptions{noBodies: true})
	require.Equal(t, marker, m["body_compaction"])
	require.NotContains(t, compactRecordView(&database.HTTPRecord{UUID: "u"}, agentViewOptions{noBodies: true}),
		"body_compaction", "an uncompacted record carries no marker")
	require.Contains(t, trafficViewFields, "body_compaction")
}
