//go:build canary

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// These canary tests exercise the "stateless single-phase" CLI workflow against
// real vulnerable apps, e.g.:
//
//	vigolium run discover   -t <url> --stateless --format jsonl,html --omit-response -o content-discovery-result
//	vigolium run spidering  -t <url> --stateless --format jsonl       --omit-response -o sample
//
// In stateless mode (pkg/cli/scan_execute.go), the scan runs against a throwaway temp
// SQLite database and results are materialized to the -o file(s) after the scan
// via finishStatelessExport. These tests reproduce that flow end-to-end:
//   1. allocate a file-based temp SQLite DB (mirrors os.CreateTemp in executeNativeScan),
//   2. run a single phase via the runner using runner.ApplyNativePhaseSelection
//      (the same --only mapping the CLI uses for `run <phase>`),
//   3. export every requested --format from the temp DB, reusing the production
//      output.GenerateHTMLReport generator and the same export-envelope shape as
//      pkg/cli/export.go queryExportData.

// setupStatelessTempDB creates a file-based temp SQLite DB matching what
// executeNativeScan allocates for a --stateless run (WAL journal), and removes
// the DB plus its -wal/-shm sidecars on cleanup.
func setupStatelessTempDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "vigolium-stateless-canary-*.sqlite")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        tmpPath,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))

	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(tmpPath)
		_ = os.Remove(tmpPath + "-wal")
		_ = os.Remove(tmpPath + "-shm")
	})
	return db, database.NewRepository(db)
}

// statelessExportItems mirrors pkg/cli/export.go queryExportData for the
// http_record + finding types, including the --omit-response behavior (drop the
// bulky raw request/response bytes, keep metadata). Each item is wrapped in the
// same {type, data} envelope the production exporter emits.
func statelessExportItems(t *testing.T, db *database.DB, omitResponse bool) []any {
	t.Helper()
	ctx := context.Background()

	var items []any

	records, err := database.NewQueryBuilder(db, database.QueryFilters{}).Execute(ctx)
	require.NoError(t, err)
	seen := make(map[string]struct{}, len(records))
	for _, r := range records {
		if _, dup := seen[r.URL]; dup {
			continue
		}
		seen[r.URL] = struct{}{}

		var data any
		if omitResponse {
			rc := *r // shallow copy; drop bulky raw bytes, keep metadata
			rc.RawRequest = nil
			rc.RawResponse = nil
			data = &rc
		} else {
			data = r
		}
		items = append(items, map[string]any{"type": "http_record", "data": data})
	}

	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{}).Execute(ctx)
	require.NoError(t, err)
	for _, f := range findings {
		items = append(items, map[string]any{"type": "finding", "data": f})
	}
	return items
}

// writeStatelessOutputs mirrors pkg/cli/scan_export.go finishStatelessExport: it
// materializes every requested --format from the temp DB to opts.Output, using
// the production HTML generator and the same JSONL envelope encoding.
func writeStatelessOutputs(t *testing.T, db *database.DB, opts *types.Options) {
	t.Helper()
	require.NotEmpty(t, opts.Output, "stateless export requires an output path")

	basePath := types.StripFormatExtension(opts.Output)
	items := statelessExportItems(t, db, opts.OmitResponse)

	for _, format := range opts.OutputFormats {
		outPath := types.FormatOutputPath(basePath, format)
		switch format {
		case "jsonl":
			f, err := os.Create(outPath)
			require.NoError(t, err)
			// Safety net: a require.NoError below calls runtime.Goexit() on
			// failure and would skip the explicit Close, leaking the FD.
			defer func() { _ = f.Close() }()
			enc := json.NewEncoder(f)
			enc.SetEscapeHTML(false)
			for _, item := range items {
				require.NoError(t, enc.Encode(item))
			}
			require.NoError(t, f.Close())
		case "html":
			meta := output.HTMLReportMeta{
				Title:      "Vigolium Scan Report",
				Version:    "canary-test",
				ScanTarget: strings.Join(opts.Targets, ", "),
			}
			require.NoError(t, output.GenerateHTMLReport(items, outPath, meta))
		default:
			t.Fatalf("writeStatelessOutputs: unsupported test format %q", format)
		}
	}
}

// runStatelessPhase reproduces `vigolium run <phase> -t <target> --stateless
// --format <formats> [--omit-response] -o <outputBase>`. It returns the temp DB
// (for post-export sanity checks) and the options with Output restored to the
// base path so callers can resolve per-format paths via OutputPathForFormat.
func runStatelessPhase(t *testing.T, target, phase, outputBase string, formats []string, omitResponse bool) (*database.DB, *types.Options) {
	t.Helper()

	db, repo := setupStatelessTempDB(t)

	opts := types.DefaultOptions()
	opts.Targets = []string{target}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.Stateless = true
	opts.OmitResponse = omitResponse
	opts.OutputFormats = formats
	opts.OnlyPhase = phase
	// Keep single-phase canary runs bounded.
	opts.DiscoverMaxDuration = 45 * time.Second
	opts.SpideringMaxDuration = 25 * time.Second

	// Resolve `--only <phase>` into the per-phase enable flags exactly as the CLI
	// does (this also normalizes the `discover`/`spitolas` aliases and forces
	// HeuristicsCheck=none).
	require.NoError(t, runner.ApplyNativePhaseSelection(opts, nil))

	// Stateless suppresses StandardWriter's live file output and exports from the
	// DB after the scan; keep Output empty for the runner, restore it for export.
	opts.Output = ""

	r, err := runner.New(opts)
	require.NoError(t, err)
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	require.NoError(t, r.RunNativeScan(), "stateless %q phase should complete without error", phase)

	opts.Output = outputBase
	writeStatelessOutputs(t, db, opts)
	return db, opts
}

// readJSONLEnvelopes parses a stateless JSONL export, returning the line count,
// a count of each envelope type, and whether any http_record carried a non-empty
// raw_response (used to assert --omit-response actually stripped raw bytes).
func readJSONLEnvelopes(t *testing.T, path string) (lineCount int, typeCounts map[string]int, sawRawResponse bool) {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	typeCounts = map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		lineCount++
		var env struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &env))
		typeCounts[env.Type]++
		// --omit-response only strips the raw bytes from http_record envelopes; a
		// finding carries its own (unrelated) raw_response string field, so scope
		// the check to http_record entries.
		if env.Type == "http_record" {
			if v, ok := env.Data["raw_response"]; ok {
				if s, _ := v.(string); s != "" {
					sawRawResponse = true
				}
			}
		}
	}
	require.NoError(t, sc.Err())
	return lineCount, typeCounts, sawRawResponse
}

// TestStatelessCanary_RunDiscover_VAmPI reproduces:
//
//	vigolium run discover -t <vampi> --stateless --format jsonl,html --omit-response -o content-discovery-result
//
// and asserts both named output files are produced from the throwaway DB, the
// JSONL holds discovered http_record entries, and --omit-response drops the raw
// response bytes.
func TestStatelessCanary_RunDiscover_VAmPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startVAmPI(t)

	base := filepath.Join(t.TempDir(), "content-discovery-result")
	db, opts := runStatelessPhase(t, app.BaseURL, "discover", base, []string{"jsonl", "html"}, true)

	jsonlPath := opts.OutputPathForFormat("jsonl")
	htmlPath := opts.OutputPathForFormat("html")
	assert.Equal(t, base+".jsonl", jsonlPath)
	assert.Equal(t, base+".html", htmlPath)

	// Both output files exist and the HTML report has real content.
	ji, err := os.Stat(jsonlPath)
	require.NoError(t, err, "jsonl output should exist")
	hi, err := os.Stat(htmlPath)
	require.NoError(t, err, "html output should exist")
	// A size check alone is tautological — the embedded ag-grid template is
	// already ~400 KB regardless of scan content. Assert the report actually
	// rendered the scan: format_html.go substitutes the target into the template
	// ({{.ScanTarget}}) and embeds the discovered records as row data, so the
	// target URL must appear in the output.
	htmlContent, err := os.ReadFile(htmlPath)
	require.NoError(t, err)
	assert.Contains(t, string(htmlContent), app.BaseURL,
		"html report should embed the scan target / discovered records, not just template boilerplate")

	// The discovery phase ingests at least the seed target, so the export is
	// non-empty and carries http_record envelopes.
	lineCount, typeCounts, sawRawResponse := readJSONLEnvelopes(t, jsonlPath)
	assert.Greater(t, lineCount, 0, "jsonl export should have at least one line")
	assert.Greater(t, typeCounts["http_record"], 0, "jsonl export should contain http_record entries")
	assert.False(t, sawRawResponse, "--omit-response should drop raw response bytes from the export")

	// Sanity: the temp DB actually captured the discovered records.
	var records []*database.HTTPRecord
	require.NoError(t, db.NewSelect().Model(&records).Scan(context.Background()))
	assert.GreaterOrEqual(t, len(records), 1, "discovery should ingest records into the temp DB")

	t.Logf("discover: %d records in temp DB | jsonl=%d bytes (%d lines, %d http_records) | html=%d bytes",
		len(records), ji.Size(), lineCount, typeCounts["http_record"], hi.Size())
}

// TestStatelessCanary_RunSpidering_JuiceShop reproduces:
//
//	vigolium run spidering -t <juiceshop> --stateless --format jsonl --omit-response -o sample
//
// Browser-based spidering needs a Chromium runtime; where one is unavailable the
// phase logs and yields zero records but never fails the scan. The test asserts
// the stateless single-phase export pipeline still produces the named file, and
// verifies http_record shape + omit-response stripping whenever the crawl
// captured traffic.
func TestStatelessCanary_RunSpidering_JuiceShop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startJuiceShop(t)

	base := filepath.Join(t.TempDir(), "sample")
	db, opts := runStatelessPhase(t, app.BaseURL, "spidering", base, []string{"jsonl"}, true)

	jsonlPath := opts.OutputPathForFormat("jsonl")
	assert.Equal(t, base+".jsonl", jsonlPath)
	_, err := os.Stat(jsonlPath)
	require.NoError(t, err, "jsonl output should exist for spidering")

	var records []*database.HTTPRecord
	require.NoError(t, db.NewSelect().Model(&records).Scan(context.Background()))

	// Browser-based spidering needs a Chromium runtime; without one the phase
	// captures nothing. The export-pipeline assertion above (the jsonl file
	// exists) is the part that is always exercised. Skip the content assertions
	// explicitly when nothing was captured — so a browserless run reports as SKIP
	// rather than a vacuous PASS — instead of guarding them behind `if len > 0`
	// where they would silently never run.
	if len(records) == 0 {
		t.Skip("spidering captured 0 records (Chromium runtime likely unavailable) — content assertions skipped")
	}

	lineCount, typeCounts, sawRawResponse := readJSONLEnvelopes(t, jsonlPath)
	// The export dedups http_records by URL, so its http_record count is bounded
	// by the raw record count rather than exactly equal to it.
	assert.LessOrEqual(t, typeCounts["http_record"], len(records),
		"deduped export should not exceed the raw captured-record count")
	assert.Greater(t, typeCounts["http_record"], 0, "captured spider traffic should serialize as http_record entries")
	assert.False(t, sawRawResponse, "--omit-response should drop raw response bytes from the export")

	t.Logf("spidering: %d records captured into temp DB | jsonl=%d lines (%d http_records)",
		len(records), lineCount, typeCounts["http_record"])
}
