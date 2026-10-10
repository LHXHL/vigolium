package base64_data_detect

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func makeHTTPCtxWithReqBody(url, reqBody, respBody string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", url, reqBody))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", respBody)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Info, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeBoth, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func TestCanProcess_Nil(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))
}

func findResultBySource(results []*output.ResultEvent, source string) *output.ResultEvent {
	for _, r := range results {
		for _, e := range r.ExtractedResults {
			if e == source {
				return r
			}
		}
	}
	return nil
}

func TestScanPerRequest_JSONBase64InResponse(t *testing.T) {
	m := New()
	// eyJ = base64 for '{"'
	body := `<input value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">`
	ctx := modtest.HTTPCtx("/page", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	respResult := findResultBySource(results, "Source: response")
	require.NotNil(t, respResult)
	assert.Equal(t, ModuleID, respResult.ModuleID)
	assert.Equal(t, "Base64 Encoded Data in Response", respResult.Info.Name)
	assert.Contains(t, respResult.Info.Tags, "base64")
}

func TestScanPerRequest_PHPArrayInResponse(t *testing.T) {
	m := New()
	// YTo = base64 for 'a:' (PHP serialized array)
	body := `data=YToxOntzOjQ6InRlc3QiO3M6NToidmFsdWUiO30=`
	ctx := modtest.HTTPCtx("/api", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_PHPObjectInResponse(t *testing.T) {
	m := New()
	// Tzo = base64 for 'O:' (PHP serialized object)
	body := `cookie=TzoxMDoiUGhwT2JqZWN0IjoxOntzOjQ6InRlc3QiO3M6NToidmFsdWUiO30=`
	ctx := modtest.HTTPCtx("/api", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_JavaSerializedInResponse(t *testing.T) {
	m := New()
	// rO0 = Java serialized object prefix
	body := `session=rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtA=`
	ctx := modtest.HTTPCtx("/api", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_HTTPSURLInResponse(t *testing.T) {
	m := New()
	// aHR0cHM6L = base64 for 'https:/'
	body := `redirect=aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg==`
	ctx := modtest.HTTPCtx("/redirect", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

func TestScanPerRequest_Base64InRequest(t *testing.T) {
	m := New()
	reqBody := "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	ctx := makeHTTPCtxWithReqBody("/api/auth", reqBody, "OK")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	reqResult := findResultBySource(results, "Source: request")
	require.NotNil(t, reqResult, "should detect base64 in request")
	assert.Equal(t, "Base64 Encoded Data in Request", reqResult.Info.Name)
}

func TestScanPerRequest_NoMatch(t *testing.T) {
	m := New()
	body := `<html><body>Hello world</body></html>`
	ctx := modtest.HTTPCtx("/page", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_MediaURL(t *testing.T) {
	m := New()
	body := `eyJhbGciOiJIUzI1NiJ9`
	ctx := modtest.HTTPCtx("/image.png", "text/html", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_NilResponse(t *testing.T) {
	m := New()
	rawReq := []byte("GET /page?data=eyJhbGciOiJIUzI1NiJ9 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	ctx := httpmsg.NewHttpRequestResponse(req, nil)

	// Module scope is Both, so CanProcess returns false when response is nil
	assert.False(t, m.CanProcess(ctx))
}

func TestIdentifyPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"eyJhbGciOiJIUzI1NiJ9", "JSON object"},
		{"YToxOntzOjQ6InRlc3QiO30=", "PHP serialized array"},
		{"TzoxMDoiUGhwT2JqZWN0Ijo=", "PHP serialized object"},
		{"PD94bWwgdmVyc2lvbj0=", "PHP tag"},
		{"PD8=", "XML declaration"},
		{"aHR0cHM6Ly9leGFtcGxlLmNvbQ==", "HTTPS URL"},
		{"aHR0cDovL2V4YW1wbGUuY29t", "HTTP URL"},
		{"rO0ABXNyABFq", "Java serialized object"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, identifyPrefix(tc.input))
		})
	}
}

func TestFindBase64Matches(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"no match", "hello world", 0},
		{"single JSON", `token=eyJhbGciOiJIUzI1NiJ9`, 1},
		{"duplicate", `a=eyJhbGci&b=eyJhbGci`, 1},
		{"multiple types", `a=eyJhbGci&b=rO0ABXNy`, 2},
		{"with url encoding", `data=eyJ%61bGci`, 1},
		{"with padding", `data=eyJhbGciOiJIUzI1NiJ9==`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := findBase64Matches(tc.input)
			assert.Len(t, matches, tc.expected)
		})
	}
}

// urlSafeJSON is base64url(`{"returnTo":"https://api.example.com/v1/auth/oidc/login/redirect?sessionState=x>?>?>?"}`).
// It contains both '-' and '_' from the URL-safe alphabet so it exercises the
// broadened capture: the old regex stopped at the first '-'/'_' and decoded to a
// truncated fragment; the value must now be captured whole and decode to valid JSON.
const urlSafeJSON = "eyJyZXR1cm5UbyI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL3YxL2F1dGgvb2lkYy9sb2dpbi9yZWRpcmVjdD9zZXNzaW9uU3RhdGU9eD4_Pj8-PyJ9"

func TestDecodeBase64Blob(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantOK  bool
		wantSub string // optional: substring the result must contain
	}{
		{name: "std JSON", input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", want: `{"alg":"HS256","typ":"JWT"}`, wantOK: true},
		{name: "url-safe JSON whole", input: urlSafeJSON, wantOK: true, wantSub: `?sessionState=x>?>?>?"}`},
		{name: "https url", input: "aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg", want: "https://example.com/login", wantOK: true},
		{name: "percent encoded", input: "eyJ%68bGciOiJIUzI1NiJ9", wantOK: true, wantSub: `{"alg`}, // %68 = 'h'
		{name: "missing padding", input: "eyJhbGciOiJIUzI1NiJ9", wantOK: true, wantSub: `{"alg`},
		{name: "garbage", input: "!!!notbase64!!!", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeBase64Blob(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			if tc.want != "" {
				assert.Equal(t, tc.want, got)
			}
			if tc.wantSub != "" {
				assert.Contains(t, got, tc.wantSub)
			}
		})
	}
}

// dm decodes a single base64 blob into a decodedMatch for tests.
func dm(s string) decodedMatch { return decodeMatches([]string{s})[0] }

func TestDisplayableDecoded_SkipsBinary(t *testing.T) {
	// rO0ABXNy... is a Java serialized object header: it decodes to bytes that
	// are not valid UTF-8 text, so no decoded line should be offered.
	assert.Empty(t, displayableDecoded(dm("rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtA=")))
	// JSON decodes to readable text.
	assert.Equal(t, `{"alg":"HS256","typ":"JWT"}`, displayableDecoded(dm("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")))
}

func TestIsDisplayableText(t *testing.T) {
	assert.True(t, isDisplayableText(`{"a":1}`))
	assert.True(t, isDisplayableText("https://example.com"))
	assert.False(t, isDisplayableText(""))
	assert.False(t, isDisplayableText("text\x00with-nul"))
	assert.False(t, isDisplayableText("\xac\xed\x00\x05")) // invalid UTF-8 binary
}

func TestBuildExtracted_IncludesDecodedLineAndPreview(t *testing.T) {
	extracted, preview := buildExtracted("request", decodeMatches([]string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}))
	require.NotEmpty(t, extracted)
	assert.Equal(t, "Source: request", extracted[0])

	var hasRaw, hasDecoded bool
	for _, line := range extracted {
		if line == "JSON object: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" {
			hasRaw = true
		}
		if line == `JSON object (decoded): {"alg":"HS256","typ":"JWT"}` {
			hasDecoded = true
		}
	}
	assert.True(t, hasRaw, "raw base64 line should be present")
	assert.True(t, hasDecoded, "decoded line should be present")
	assert.Equal(t, `{"alg":"HS256","typ":"JWT"}`, preview)
}

func TestBuildExtracted_BinaryHasNoDecodedLine(t *testing.T) {
	extracted, preview := buildExtracted("response", decodeMatches([]string{"rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtA="}))
	assert.Empty(t, preview)
	for _, line := range extracted {
		assert.NotContains(t, line, "(decoded)")
	}
}

func TestScanPerRequest_URLSafeBlobDecodedEndToEnd(t *testing.T) {
	m := New()
	ctx := modtest.HTTPCtx("/login?authctx="+urlSafeJSON, "text/html", "OK")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)

	reqResult := findResultBySource(results, "Source: request")
	require.NotNil(t, reqResult, "URL-safe base64 in the request line should be detected")

	var decodedLine string
	for _, line := range reqResult.ExtractedResults {
		if strings.Contains(line, "(decoded)") {
			decodedLine = line
		}
	}
	require.NotEmpty(t, decodedLine, "a decoded line should be present")
	// The whole blob (past the '-'/'_') must decode to complete JSON.
	assert.Contains(t, decodedLine, `"returnTo":"https://api.example.com`)
	assert.Contains(t, decodedLine, `sessionState=x>?>?>?"}`)
	// The decoded preview should also surface in the finding description.
	assert.Contains(t, reqResult.Info.Description, "Decoded preview:")
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func mustScanResp(t *testing.T, m *Module, ctx *httpmsg.HttpRequestResponse) *output.ResultEvent {
	t.Helper()
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	return findResultBySource(results, "Source: response")
}

// TestStructuralSignatureCoalescesRotatingJSON is the grouping fix: a framework
// token like {"nonce":...} that rotates its value on every page must collapse to a
// single finding identity across URLs on a host, while a differently-shaped blob
// keeps its own identity.
func TestStructuralSignatureCoalescesRotatingJSON(t *testing.T) {
	m := New()

	a := mustScanResp(t, m, modtest.HTTPCtx("/p1", "text/html", `x="`+b64(`{"nonce":"AAAAAAAAAAAA"}`)+`"`))
	b := mustScanResp(t, m, modtest.HTTPCtx("/p2", "text/html", `x="`+b64(`{"nonce":"BBBBBBBBBBBB"}`)+`"`))
	require.NotNil(t, a)
	require.NotNil(t, b)
	require.NotEmpty(t, a.DedupKey, "JSON blob should get a structural dedup key")
	assert.Equal(t, a.DedupKey, b.DedupKey, "same JSON shape + host should coalesce")
	assert.Equal(t, a.ID(), b.ID(), "coalesced findings share one identity hash")

	// A different JSON shape is a distinct signal → distinct identity.
	c := mustScanResp(t, m, modtest.HTTPCtx("/p3", "text/html", `x="`+b64(`{"apiKey":"secret-value-here-1234"}`)+`"`))
	require.NotNil(t, c)
	assert.NotEqual(t, a.DedupKey, c.DedupKey, "different JSON shape must not coalesce")
}

func TestStructuralSignatureBailsOnNonJSON(t *testing.T) {
	// A non-JSON blob (an HTTPS URL) must NOT coalesce — its distinct value may be
	// the signal, so it keeps the default content-based identity.
	if _, ok := structuralSignature(decodeMatches([]string{b64("https://example.com/secret-path-value")})); ok {
		t.Fatal("non-JSON blob should not produce a structural signature")
	}
	if _, ok := structuralSignature(decodeMatches([]string{"not-decodable"})); ok {
		t.Fatal("undecodable blob should bail")
	}
	if _, ok := structuralSignature(nil); ok {
		t.Fatal("empty matches should bail")
	}
	// A JSON object yields a stable, value-independent signature.
	sig1, ok1 := structuralSignature(decodeMatches([]string{b64(`{"nonce":"one"}`)}))
	sig2, ok2 := structuralSignature(decodeMatches([]string{b64(`{"nonce":"two-different"}`)}))
	if !ok1 || !ok2 || sig1 != sig2 {
		t.Fatalf("same JSON shape should share a signature: %q(%v) vs %q(%v)", sig1, ok1, sig2, ok2)
	}
}
