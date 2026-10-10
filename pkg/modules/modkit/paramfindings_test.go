package modkit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func paramKeyItem(t *testing.T, host, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure(host, 443, true), raw)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func TestParamFindingKey_Normalization(t *testing.T) {
	assert.Equal(t, "https://example.com/users", ParamFindingKey(paramKeyItem(t, "Example.COM", "/users?id=1")),
		"host is lowercased and the query dropped")
	assert.Equal(t, "", ParamFindingKey(nil))

	assert.Equal(t, "https://example.com/", normalizeParamFindingLocation("HTTPS", " Example.com ", ""),
		"empty path becomes / and scheme/host case folds")
	assert.Equal(t, "example.com/a", normalizeParamFindingLocation("", "example.com", "a"))
}

func TestParamFindingKey_ItemAndResultAgree(t *testing.T) {
	item := paramKeyItem(t, "example.com", "/users?id=1")
	for _, r := range []*output.ResultEvent{
		{URL: "https://EXAMPLE.com/users?id=2"},
		{Matched: "https://example.com/users"},
		{Scheme: "https", Request: "GET /users?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"},
	} {
		assert.Equal(t, ParamFindingKey(item), ParamFindingKeyFromResult(r))
	}
}

func TestScanContext_ParamAlreadyFound(t *testing.T) {
	item := paramKeyItem(t, "example.com", "/search?q=1")
	other := paramKeyItem(t, "example.com", "/other?q=1")

	var nilCtx *ScanContext
	assert.False(t, nilCtx.ParamAlreadyFound(item, "q", VulnClassXSS))
	nilCtx.MarkParamFound(item, "q", VulnClassXSS) // must not panic

	bare := &ScanContext{}
	bare.MarkParamFound(item, "q", VulnClassXSS)
	assert.False(t, bare.ParamAlreadyFound(item, "q", VulnClassXSS), "no registry: dedup disabled")

	sc := &ScanContext{ParamFindings: &ParameterFindingRegistry{}}
	sc.MarkParamFound(item, "q", VulnClassXSS)
	assert.True(t, sc.ParamAlreadyFound(item, "q", VulnClassXSS))
	assert.True(t, sc.ParamAlreadyFound(paramKeyItem(t, "EXAMPLE.com", "/search?q=2&z=3"), "q", VulnClassXSS))
	assert.False(t, sc.ParamAlreadyFound(item, "q", VulnClassXSSStored), "classes are independent")
	assert.False(t, sc.ParamAlreadyFound(item, "z", VulnClassXSS))
	assert.False(t, sc.ParamAlreadyFound(other, "q", VulnClassXSS))
	assert.False(t, sc.ParamAlreadyFound(item, "q", ""), "an unclassified module never skips")

	sc.NoParamDedup = true
	assert.False(t, sc.ParamDedupEnabled())
	assert.False(t, sc.ParamAlreadyFound(item, "q", VulnClassXSS), "--no-param-dedup disables the skip")
}
