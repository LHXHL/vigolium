package cli

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// The csv report's columns are finding view keys: every column is a key
// `finding -j` (compactFindingView) prints for the same stored row, with the
// same value. A stored finding goes through the export envelope the report
// renderers read, exactly as `export --format csv` and `scan --format csv`
// hand it over.
func TestCSVReportColumnsMatchFindingView(t *testing.T) {
	f := &database.Finding{
		ID:              42,
		ProjectUUID:     "proj-1",
		HTTPRecordUUIDs: []string{"rec-1", "rec-2"},
		ScanUUID:        "scan-1",
		URL:             "https://shop.example/item?id=1",
		Hostname:        "shop.example",
		ModuleID:        "sqli-error",
		ModuleName:      "SQL Injection (error-based)",
		ModuleShort:     "Error-based SQL injection",
		Severity:        "high",
		Confidence:      "firm",
		Status:          "triaged",
		CWEID:           "CWE-89",
		SourceFile:      "app/db.py:12",
		RepoName:        "shop",
		MatchedAt:       []string{"https://shop.example/item?id=1", "id"},
		FindingHash:     strings.Repeat("a", 40),
		FoundAt:         time.Date(2026, 10, 10, 1, 2, 3, 456, time.UTC),
	}
	view := compactFindingView(f, nil, agentViewOptions{noBodies: true})

	out := filepath.Join(t.TempDir(), "findings.csv")
	require.NoError(t, output.GenerateCSVReport([]any{exportEnvelope{Type: "finding", Data: f}}, out, output.HTMLReportMeta{}))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, output.FindingCSVColumns, rows[0])

	for i, col := range output.FindingCSVColumns {
		want, ok := view[col]
		require.True(t, ok, "csv column %q is not a finding -j key", col)
		var s string
		switch v := want.(type) {
		case []string:
			s = strings.Join(v, "; ")
		default:
			s = fmt.Sprint(v)
		}
		assert.Equal(t, s, rows[1][i], "column %q", col)
	}
}
