package har

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func parseFixture(t *testing.T, name string) []*httpmsg.HttpRequestResponse {
	t.Helper()
	var out []*httpmsg.HttpRequestResponse
	err := New().Parse(filepath.Join("testdata", name), func(rr *httpmsg.HttpRequestResponse) bool {
		out = append(out, rr)
		return true
	})
	require.NoError(t, err)
	return out
}

func TestFixture_ChromeH2(t *testing.T) {
	rrs := parseFixture(t, "chrome_h2.har")
	require.Len(t, rrs, 4)

	t.Run("h2 request and gzip response", func(t *testing.T) {
		rr := rrs[0]
		assert.Equal(t,
			"GET /api/items?page=2 HTTP/1.1\r\n"+
				"Host: app.example.test\r\n"+
				"accept: application/json\r\n"+
				"accept-encoding: gzip, deflate, br\r\n"+
				"\r\n",
			string(rr.Request().Raw()))
		require.True(t, rr.HasResponse())
		// Empty statusText comes from http.StatusText; content.text is already
		// decoded, so Content-Encoding goes and Content-Length is recomputed.
		assert.Equal(t,
			"HTTP/1.1 200 OK\r\n"+
				"content-length: 19\r\n"+
				"content-type: application/json\r\n"+
				"\r\n"+
				"{\"items\":[1,2,3]}  ",
			string(rr.Response().Raw()))
	})

	t.Run("h3 base64 image", func(t *testing.T) {
		rr := rrs[1]
		assert.Equal(t,
			"GET /logo.png HTTP/1.1\r\nHost: cdn.example.test\r\naccept: image/png\r\n\r\n",
			string(rr.Request().Raw()))
		png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0x0d}
		assert.Equal(t, png, rr.Response().Body())
		assert.Equal(t, "12", rr.Response().Header("content-length"))
		assert.Equal(t, 200, rr.Response().StatusCode())
	})

	t.Run("multipart params", func(t *testing.T) {
		rr := rrs[2]
		body := "------WebKitFormBoundaryABC123\r\n" +
			"Content-Disposition: form-data; name=\"title\"\r\n\r\n" +
			"hello\r\n" +
			"------WebKitFormBoundaryABC123\r\n" +
			"Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n" +
			"Content-Type: text/plain\r\n\r\n" +
			"\r\n" +
			"------WebKitFormBoundaryABC123--\r\n"
		assert.Equal(t, body, string(rr.Request().Body()))
		assert.Equal(t, "multipart/form-data; boundary=----WebKitFormBoundaryABC123", rr.Request().Header("Content-Type"))
		assert.Equal(t, "246", rr.Request().Header("Content-Length"))
		assert.Len(t, body, 246)
		assert.Equal(t, "HTTP/1.1 404 Not Found\r\n\r\n", string(rr.Response().Raw()))
	})

	t.Run("urlencoded params", func(t *testing.T) {
		rr := rrs[3]
		assert.Equal(t,
			"POST /login HTTP/1.1\r\n"+
				"Host: app.example.test\r\n"+
				"content-type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 27\r\n"+
				"\r\n"+
				"user=alice&pass=p%26ss+word",
			string(rr.Request().Raw()))
		assert.Equal(t, "HTTP/1.1 302 Found\r\nlocation: /home\r\n\r\n", string(rr.Response().Raw()))
	})
}

func TestFixture_Firefox(t *testing.T) {
	rrs := parseFixture(t, "firefox.har")
	require.Len(t, rrs, 1)
	rr := rrs[0]
	assert.Equal(t,
		"POST /api/cart HTTP/1.1\r\n"+
			"Host: shop.example.test\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: 12\r\n"+
			"\r\n"+
			"{\"sku\":\"A1\"}",
		string(rr.Request().Raw()))
	assert.Equal(t,
		"HTTP/1.1 201 Created\r\n"+
			"content-type: application/json\r\n"+
			"Content-Length: 11\r\n"+
			"\r\n"+
			"{\"ok\":true}",
		string(rr.Response().Raw()))
}

func TestBuildRequestBody_GeneratedBoundary(t *testing.T) {
	req := &harRequest{
		Method: "POST",
		URL:    "https://example.test/u",
		PostData: &harPost{
			MimeType: "multipart/form-data",
			Params:   []harParam{{Name: "a", Value: "1"}},
		},
	}
	raw := buildRawRequest(req)
	assert.Contains(t, raw, "Content-Type: multipart/form-data; boundary="+defaultMultipartBoundary+"\r\n")
	assert.Contains(t, raw, "--"+defaultMultipartBoundary+"\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n")
}

func TestNormalizeHTTPVersion(t *testing.T) {
	for in, want := range map[string]string{
		"h2": "HTTP/1.1", "HTTP/2": "HTTP/1.1", "HTTP/2.0": "HTTP/1.1", "http/2.0": "HTTP/1.1",
		"h3": "HTTP/1.1", "": "HTTP/1.1", "unknown": "HTTP/1.1", "HTTP/1.1": "HTTP/1.1", "HTTP/1.0": "HTTP/1.0",
	} {
		assert.Equal(t, want, normalizeHTTPVersion(in), in)
	}
}
