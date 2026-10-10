package output

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// ciFixtureItems is the seeded finding set behind the csv/junit/github goldens:
// two modules, one with two hosts, a below-threshold info finding, a dismissed
// finding, a code finding with a source line, and hostile cell content.
func ciFixtureItems() []any {
	finding := func(fields map[string]any) any {
		return map[string]any{"type": "finding", "data": fields}
	}
	return []any{
		map[string]any{"type": "scan", "data": map[string]any{"target": "https://shop.example"}},
		finding(map[string]any{
			"id": 12, "module_id": "sqli-error", "module_name": "SQL Injection (error-based)",
			"module_short": "Error-based SQL injection", "severity": "high", "confidence": "firm",
			"cwe_id": "CWE-89", "url": "https://shop.example/item?id=1'", "hostname": "shop.example",
			"matched_at":   []string{"https://shop.example/item?id=1'", "id"},
			"request":      "GET /item?id=1' HTTP/1.1\nHost: shop.example\n\n",
			"finding_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "scan_uuid": "scan-1",
			"http_record_uuids": []string{"rec-1", "rec-2"}, "status": "triaged",
			"found_at": "2026-10-10T00:00:00Z", "created_at": "2026-10-10T00:00:01Z",
		}),
		finding(map[string]any{
			"id": 13, "module_id": "sqli-error", "module_name": "SQL Injection (error-based)",
			"module_short": "Error-based SQL injection", "severity": "critical", "confidence": "certain",
			"url": "https://api.example/v1/users", "hostname": "api.example",
			"request":      "POST /v1/users HTTP/1.1\nHost: api.example\n\n",
			"finding_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "scan_uuid": "scan-1",
			"status": "confirmed", "found_at": "2026-10-10T00:00:02Z",
		}),
		finding(map[string]any{
			"id": 14, "module_id": "tech-detect", "module_name": "Technology =HYPERLINK(\"x\")",
			"severity": "info", "url": "https://shop.example/", "hostname": "shop.example",
			"matched_at":   []string{"+cmd|' /C calc'!A0", "@SUM(1,1)"},
			"finding_hash": "cccccccccccccccccccccccccccccccccccccccc", "status": "triaged",
		}),
		finding(map[string]any{
			"id": 15, "module_id": "tech-detect", "module_name": "Technology",
			"severity": "medium", "url": "https://shop.example/admin", "hostname": "shop.example",
			"finding_hash": "dddddddddddddddddddddddddddddddddddddddd", "status": "false_positive",
		}),
		finding(map[string]any{
			"id": 16, "module_id": "audit-hardcoded-secret", "module_name": "Hardcoded secret, in config: key",
			"severity": "medium", "source_file": "/src/shop-api/app/config.py:42", "repo_name": "shop-api",
			"finding_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "description": "line one\nline two 100%",
		}),
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", name)
	if *updateGolden {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(golden, got, 0o644))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err, "missing golden; run with -update")
	assert.Equal(t, string(want), string(got))
}

// Regenerate the goldens with: go test ./pkg/output -run Golden -update
func TestGenerateCSVReportGolden(t *testing.T) {
	out := filepath.Join(t.TempDir(), "findings.csv")
	require.NoError(t, GenerateCSVReport(ciFixtureItems(), out, HTMLReportMeta{}))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assertGolden(t, "findings.csv.golden", got)

	rows, err := csv.NewReader(bytes.NewReader(got)).ReadAll()
	require.NoError(t, err, "the CSV must parse back")
	require.Len(t, rows, 6)
	assert.Equal(t, FindingCSVColumns, rows[0])
	col := func(name string) int {
		for i, c := range FindingCSVColumns {
			if c == name {
				return i
			}
		}
		t.Fatalf("no column %s", name)
		return -1
	}
	assert.Equal(t, "rec-1; rec-2", rows[1][col("record_uuids")])
	assert.Equal(t, "GET", rows[1][col("method")])
	assert.Equal(t, "shop.example", rows[1][col("host")])
	assert.Equal(t, "scan-1", rows[1][col("scan_uuid")])
	assert.Equal(t, "'+cmd|' /C calc'!A0; @SUM(1,1)", rows[3][col("matched_at")],
		"a formula-leading cell is neutralized; only the leading character matters")
	assert.Equal(t, "shop-api", rows[5][col("host")], "code findings fall back to the repository")
}

func TestSanitizeCSVField(t *testing.T) {
	for _, in := range []string{"=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"} {
		assert.Equal(t, "'"+in, SanitizeCSVField(in), "%q", in)
	}
	for _, in := range []string{"", "plain", "a=b", " =x", "https://x/?a=-1"} {
		assert.Equal(t, in, SanitizeCSVField(in), "%q", in)
	}
}

// TestSafeCSVWriterQuotesAndGuards: hostile content round-trips through a CSV
// parser as one cell each, with the formula guard applied.
func TestSafeCSVWriterQuotesAndGuards(t *testing.T) {
	var buf bytes.Buffer
	w := NewSafeCSVWriter(&buf)
	row := []string{"a,b", "say \"hi\"", "line\r\nbreak", "=HYPERLINK(\"http://evil\")", "-2+3"}
	require.NoError(t, w.Write(row))
	require.NoError(t, w.Flush())
	got, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, []string{"a,b", "say \"hi\"", "line\nbreak", "'=HYPERLINK(\"http://evil\")", "'-2+3"}, got[0])
}

func TestGenerateJUnitReportGolden(t *testing.T) {
	out := filepath.Join(t.TempDir(), "findings.junit.xml")
	require.NoError(t, GenerateJUnitReport(ciFixtureItems(), out, HTMLReportMeta{Title: "Golden", FailOn: "medium"}))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assertGolden(t, "findings.junit.golden", got)

	var doc junitTestSuites
	require.NoError(t, xml.Unmarshal(got, &doc), "the JUnit XML must parse back")
	assert.Equal(t, 4, doc.Tests, "one testcase per (module, host)")
	assert.Equal(t, 3, doc.Failures, "sqli on two hosts + the medium audit finding")
	require.Len(t, doc.Suites, 3)
	assert.Equal(t, []string{"audit-hardcoded-secret", "sqli-error", "tech-detect"},
		[]string{doc.Suites[0].Name, doc.Suites[1].Name, doc.Suites[2].Name}, "one suite per module, sorted")
	tech := doc.Suites[2].Cases[0]
	assert.Empty(t, tech.Failures, "info is below the medium threshold and medium is dismissed")
	assert.Contains(t, tech.SystemOut, "[below threshold]")
	assert.Contains(t, tech.SystemOut, "[status false_positive]")
	assert.Contains(t, doc.Suites[1].Cases[0].Failures[0].Message, "finding_hash bbbbbbbbbbbb")
}

func TestJUnitThresholdDefaultsAndSkips(t *testing.T) {
	findings := collectReportFindings(ciFixtureItems())
	doc := buildJUnitReport(findings, HTMLReportMeta{})
	assert.Equal(t, 3, doc.Failures, "default threshold is low: info does not fail")
	assert.Equal(t, DefaultJUnitFailOn, doc.Suites[0].Properties[0].Value)

	doc = buildJUnitReport(findings, HTMLReportMeta{FailOn: "critical"})
	assert.Equal(t, 1, doc.Failures)

	dismissed := []ReportFinding{{ModuleID: "m", Hostname: "h", Severity: "high", Status: "accepted_risk"}}
	doc = buildJUnitReport(dismissed, HTMLReportMeta{})
	require.Len(t, doc.Suites, 1)
	assert.NotNil(t, doc.Suites[0].Cases[0].Skipped)
	assert.Equal(t, 1, doc.Skipped)
}

func TestGenerateGitHubAnnotationsGolden(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	out := filepath.Join(t.TempDir(), "findings.github.txt")
	require.NoError(t, GenerateGitHubAnnotations(ciFixtureItems(), out, HTMLReportMeta{}))
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assertGolden(t, "findings.github.golden", got)

	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	require.Len(t, lines, 4, "the dismissed finding is left out")
	assert.True(t, strings.HasPrefix(lines[0], "::error "), "critical first")
	for _, l := range lines {
		assert.NotContains(t, l, "\r")
	}
	assert.Contains(t, string(got), "file=app/config.py,line=42", "code findings anchor to a repo-relative file and line")
	assert.Contains(t, string(got), "title=[medium] Hardcoded secret%2C in config%3A key", "property delimiters are escaped")
}

func TestGenerateGitHubAnnotationsStdoutAndStepSummary(t *testing.T) {
	var buf bytes.Buffer
	prev := reportStdout
	reportStdout = &buf
	t.Cleanup(func() { reportStdout = prev })

	summary := filepath.Join(t.TempDir(), "summary.md")
	require.NoError(t, os.WriteFile(summary, []byte("previous step\n"), 0o644))
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	require.NoError(t, GenerateGitHubAnnotations(ciFixtureItems(), "", HTMLReportMeta{Title: "CI"}))
	assert.Contains(t, buf.String(), "::error ")
	data, err := os.ReadFile(summary)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(data), "previous step\n"), "the summary is appended, not replaced")
	assert.Contains(t, string(data), "# CI")
	assert.Contains(t, string(data), "## Executive Summary")
}

func TestGitHubEscaping(t *testing.T) {
	assert.Equal(t, "a%25b%0D%0Ac", githubEscapeData("a%b\r\nc"))
	assert.Equal(t, "a%3Ab%2Cc%0A", githubEscapeProperty("a:b,c\n"))
	assert.Equal(t, "error", githubLevel("critical"))
	assert.Equal(t, "warning", githubLevel("low"))
	assert.Equal(t, "notice", githubLevel("suspect"))
	assert.Equal(t, "notice", githubLevel(""))
}

func TestErrPDFFailedCarriesCode(t *testing.T) {
	err := errors.Join(errors.New("other"), errors.New("x"))
	wrapped := errors.Join(err, errors.Join(ErrPDFFailed))
	var coded interface{ Code() apicontract.ErrorCode }
	require.True(t, errors.As(wrapped, &coded))
	assert.Equal(t, apicontract.CodePDFFailed, coded.Code())
	assert.True(t, errors.Is(wrapped, ErrPDFFailed))
}

// TestFormatRegistryRenderers keeps the renderer bindings and the format table
// in lockstep: every report format renders, and nothing else has a renderer.
func TestFormatRegistryRenderers(t *testing.T) {
	for _, s := range []Surface{SurfaceScan, SurfaceExport, SurfaceImport, SurfaceREST} {
		for _, f := range ReportFormats(s) {
			assert.NotNil(t, f.Render, "%s has no renderer", f.Name)
			assert.NotEmpty(t, f.DefaultTitle, f.Name)
		}
	}
	for name := range reportRenderers {
		f, ok := FormatByName(name)
		require.True(t, ok, "renderer bound to unknown format %q", name)
		assert.Equal(t, KindReport, f.Kind, "renderer bound to non-report format %q", name)
	}
	md, err := Lookup("MD", SurfaceScan)
	require.NoError(t, err)
	assert.Equal(t, "markdown", md.Name)
	assert.NotNil(t, md.Render)
}
