package output

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files under testdata/")

func TestMarkdownFence(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"plain", "GET / HTTP/1.1", "```"},
		{"single backtick", "a `b` c", "```"},
		{"triple backticks inside", "body\n```js\nx\n```\n", "````"},
		{"quad backticks inside", "````md\n```\n````", "`````"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			open, closeFence := MarkdownFence(tt.body, "http")
			assert.Equal(t, tt.want+"http", open)
			assert.Equal(t, tt.want, closeFence)
		})
	}
}

func TestMarkdownCodeSpan(t *testing.T) {
	assert.Equal(t, "`plain`", MarkdownCodeSpan("plain"))
	assert.Equal(t, "``a`b``", MarkdownCodeSpan("a`b"))
	assert.Equal(t, "`` `x ``", MarkdownCodeSpan("`x"))
	assert.Equal(t, "`a b`", MarkdownCodeSpan("a\nb"))
}

// A response that itself contains ``` and ```` must stay inside its block:
// the fence is longer than any run in the body, and the only lines made purely
// of that fence are the opening and closing ones.
func TestWriteMarkdownFindingsFenceSurvivesBackticks(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/markdown\r\n\r\n# README\n```bash\nmake\n```\n````\nquad\n````\n"
	w := &strings.Builder{}
	writeMarkdownFindings(w, "High", []ReportFinding{{
		ID: 7, Title: "t", Severity: "high", Request: "GET /readme HTTP/1.1", Response: resp,
	}}, newMarkdownFindingOptions(HTMLReportMeta{}))
	got := w.String()
	assert.Contains(t, got, "`````http\nHTTP/1.1 200 OK")
	closing := 0
	for _, line := range strings.Split(got, "\n") {
		if line == "`````" {
			closing++
		}
	}
	assert.Equal(t, 1, closing, "exactly one closing fence for the response block")
	assert.Contains(t, got, "```http\nGET /readme HTTP/1.1\n```", "request needs only the default fence")
}

func TestWriteMarkdownFindingsTruncatesSymmetrically(t *testing.T) {
	big := strings.Repeat("é", 3000) // 6000 bytes, 2 bytes per rune
	w := &strings.Builder{}
	writeMarkdownFindings(w, "High", []ReportFinding{{
		ID: 9, Title: "t", Severity: "high",
		Request:     "POST /a HTTP/1.1\r\n\r\n" + big,
		Response:    "HTTP/1.1 200 OK\r\n\r\n" + big,
		RecordUUIDs: []string{"rec-1"},
	}}, newMarkdownFindingOptions(HTMLReportMeta{MaxBodyBytes: 1001}))
	got := w.String()
	assert.True(t, utf8.ValidString(got), "a cut must never split a multibyte rune")
	assert.Contains(t, got, "… [truncated, 1000 of 6020 bytes; full: vigolium traffic body --uuid rec-1 --request]")
	assert.Contains(t, got, "… [truncated, 1001 of 6019 bytes; full: vigolium traffic body --uuid rec-1]")
}

func TestWriteMarkdownFindingsTruncationFallsBackToFinding(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownFindings(w, "Low", []ReportFinding{{
		ID: 3, Title: "t", Severity: "low", Response: strings.Repeat("x", 50),
	}}, newMarkdownFindingOptions(HTMLReportMeta{MaxBodyBytes: 10}))
	assert.Contains(t, w.String(), "… [truncated, 10 of 50 bytes; full: vigolium finding --id 3 --markdown --full-body]")
}

func TestWriteMarkdownFindingsNegativeCapKeepsWholeBody(t *testing.T) {
	w := &strings.Builder{}
	body := strings.Repeat("x", 10000)
	writeMarkdownFindings(w, "Low", []ReportFinding{{ID: 3, Title: "t", Severity: "low", Response: body}},
		newMarkdownFindingOptions(HTMLReportMeta{MaxBodyBytes: -1}))
	assert.Contains(t, w.String(), body)
	assert.NotContains(t, w.String(), "[truncated")
}

func TestWriteMarkdownFindingsMetadataAndFollowUp(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownFindings(w, "High", []ReportFinding{{
		ID: 12, Title: "t", Severity: "high", ModuleID: "sqli-error",
		FindingHash: "abc123", ScanUUID: "scan-1", RecordUUIDs: []string{"r1", "r2"},
	}}, newMarkdownFindingOptions(HTMLReportMeta{
		FollowUp: func(tail ...string) string {
			return "vigolium --db /tmp/x.sqlite " + strings.Join(tail, " ")
		},
	}))
	got := w.String()
	for _, want := range []string{
		"| finding_id | `12` |",
		"| finding_hash | `abc123` |",
		"| scan_uuid | `scan-1` |",
		"| module_id | `sqli-error` |",
		"| record_uuids | `r1`, `r2` |",
		"**Follow-up:** `vigolium --db /tmp/x.sqlite finding --id 12`",
	} {
		assert.Contains(t, got, want)
	}
}

func TestWriteMarkdownFindingsSuppressedFollowUp(t *testing.T) {
	w := &strings.Builder{}
	writeMarkdownFindings(w, "High", []ReportFinding{{ID: 12, Title: "t", Severity: "high"}},
		newMarkdownFindingOptions(HTMLReportMeta{FollowUp: func(...string) string { return "" }}))
	assert.NotContains(t, w.String(), "Follow-up")
}

func TestParseFindingCarriesScanAndRecordUUIDs(t *testing.T) {
	raw := json.RawMessage(`{"id":4,"module_id":"m","severity":"low","finding_hash":"h","scan_uuid":"s-1","http_record_uuids":["a","b"]}`)
	rf := parseFinding(raw, nil)
	assert.Equal(t, "s-1", rf.ScanUUID)
	assert.Equal(t, []string{"a", "b"}, rf.RecordUUIDs)
	assert.Equal(t, "h", rf.FindingHash)
}

// TestGenerateMarkdownReportGolden pins the whole rendered report for a seeded
// finding. Regenerate with: go test ./pkg/output -run Golden -update
func TestGenerateMarkdownReportGolden(t *testing.T) {
	items := []any{
		map[string]any{"type": "scan", "data": map[string]any{"target": "https://shop.example", "total_requests": 3}},
		map[string]any{"type": "finding", "data": map[string]any{
			"id":                12,
			"module_id":         "sqli-error",
			"module_name":       "SQL Injection (error-based)",
			"module_short":      "Error-based SQL injection",
			"severity":          "high",
			"confidence":        "firm",
			"cwe_id":            "CWE-89",
			"url":               "https://shop.example/item?id=1'",
			"description":       "The `id` parameter reaches a SQL query.",
			"matched_at":        []string{"https://shop.example/item?id=1'"},
			"extracted_results": []string{"You have an error in your SQL syntax"},
			"request":           "GET /item?id=1' HTTP/1.1\r\nHost: shop.example\r\n\r\n",
			"response":          "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nYou have an error in your SQL syntax near ```'``` — 日本語 " + strings.Repeat("ü", 40),
			"finding_hash":      "f00dfeed",
			"scan_uuid":         "11111111-2222-3333-4444-555555555555",
			"http_record_uuids": []string{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
			"found_at":          "2026-10-10T00:00:00Z",
		}},
	}
	out := filepath.Join(t.TempDir(), "report.md")
	require.NoError(t, GenerateMarkdownReport(items, out, HTMLReportMeta{
		Title:        "Golden Report",
		Version:      "v0.0.0-test",
		GeneratedAt:  "2026-10-10 00:00 UTC",
		MaxBodyBytes: 140,
	}))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.True(t, utf8.Valid(got))

	golden := filepath.Join("testdata", "markdown_report.golden")
	if *updateGolden {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(golden, got, 0o644))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "missing golden; run with -update")
	assert.Equal(t, string(want), string(got))
}
