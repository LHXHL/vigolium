package infra

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// makeCtx builds an HttpRequestResponse for the given method and path so the
// filter predicate can be exercised against realistic request shapes.
func makeCtx(t *testing.T, method, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n\r\n", method, path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		raw,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)
	return ctx
}

func TestIsValidForInjectionVulns(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"plain GET endpoint", "GET", "/api/users", true},
		{"query path with dynamic param", "GET", "/search?q=test", true},
		{"POST endpoint", "POST", "/login", true},
		{"PUT endpoint", "PUT", "/items/1", true},
		{"path with no extension", "GET", "/products/42", true},
		{"OPTIONS method rejected", "OPTIONS", "/api/users", false},
		{"CONNECT method rejected", "CONNECT", "/api/users", false},
		{"static js file rejected", "GET", "/assets/app.js", false},
		{"css file rejected", "GET", "/styles/main.css", false},
		{"png image rejected", "GET", "/images/logo.png", false},
		{"jpg image rejected", "GET", "/photo.jpg", false},
		{"woff font rejected", "GET", "/fonts/icon.woff", false},
		{"svg rejected", "GET", "/icon.svg", false},
		{"pdf rejected", "GET", "/doc.pdf", false},
		{"json file rejected", "GET", "/data.json", false},
		{"zip archive rejected", "GET", "/archive.zip", false},
		{"media URL with OPTIONS still rejected", "OPTIONS", "/icon.svg", false},
		{"cloudflare challenge-platform rejected", "POST", "/cdn-cgi/challenge-platform/h/b/fo/123", false},
		{"cloudflare trace rejected", "GET", "/cdn-cgi/trace", false},
		{"cdn-cgi bare path rejected", "GET", "/cdn-cgi", false},
		{"app path containing cdn-cgi substring allowed", "GET", "/app/cdn-cgi-report", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := makeCtx(t, tc.method, tc.path)
			urlx, err := ctx.URL()
			require.NoError(t, err)

			got := IsValidForInjectionVulns(urlx, ctx)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestLooksLikeURLParam(t *testing.T) {
	// Name-based matches.
	require.True(t, LooksLikeURLParam("redirect_url", "anything"))
	require.True(t, LooksLikeURLParam("callback", "x"))
	require.True(t, LooksLikeURLParam("image_url", "x"))
	require.True(t, LooksLikeURLParam("proxy", "x"))
	// Value-based matches.
	require.True(t, LooksLikeURLParam("q", "http://internal/"))
	require.True(t, LooksLikeURLParam("q", "https://internal/"))
	require.True(t, LooksLikeURLParam("q", "//internal/"))
	// Neither name nor value suggests a URL.
	require.False(t, LooksLikeURLParam("q", "hello"))
	require.False(t, LooksLikeURLParam("name", "alice"))
	require.False(t, LooksLikeURLParam("count", "42"))
}

func TestLooksLikeURLParam_BlindSSRFNames(t *testing.T) {
	positives := []string{
		// substring fragments
		"webhook", "webhookUrl", "slack_webhook", "avatar", "avatarSource",
		"continue", "continueTo", "domain", "targetDomain", "origin_url",
		"returnurl", "uri_template",
		// whole-token fragments
		"hook", "hook_target", "image", "profileImage", "img", "img-src",
		"icon", "favicon_icon", "logo", "companyLogo", "feed", "rss.feed",
		"next", "nextPage", "return", "returnTo", "smtpHost", "host_name",
		"site", "site[0]", "out", "out_link", "to", "redirect-to", "ReturnURL",
	}
	for _, name := range positives {
		require.Truef(t, LooksLikeURLParam(name, "x"), "%q should look like a URL param", name)
	}

	// Short tokens must not match as substrings of unrelated words.
	negatives := []string{
		"ghost", "context", "contextId", "token", "photo", "total", "timeout",
		"layout", "logout", "feedback", "website_count", "outcome", "hostess",
		"nextgen", "returned", "icons", "imgs", "stock", "customer_id",
	}
	for _, name := range negatives {
		require.Falsef(t, LooksLikeURLParam(name, "x"), "%q must not look like a URL param", name)
	}

	// "host" is also a standard request header. Name-only callers keep excluding
	// it; typed callers exclude only the header, so a ?host= query param qualifies.
	require.False(t, LooksLikeURLParam("host", "internal.example"))
	require.False(t, LooksLikeURLParamAt(httpmsg.INS_HEADER, "Host", "internal.example"))
	require.True(t, LooksLikeURLParamAt(httpmsg.INS_PARAM_URL, "host", "internal.example"))
	require.True(t, LooksLikeURLParamAt(httpmsg.INS_PARAM_JSON, "host", "x"))
	require.False(t, LooksLikeURLParamAt(httpmsg.INS_HEADER, "Origin", "https://a.example"))
}

func TestParamNameTokens(t *testing.T) {
	cases := map[string][]string{
		"returnUrl":     {"return", "url"},
		"returnURLPath": {"return", "url", "path"},
		"img2":          {"img", "2"},
		"site[0].host":  {"site", "0", "host"},
		"redirect-to":   {"redirect", "to"},
		"HOST":          {"host"},
		"":              nil,
	}
	for in, want := range cases {
		require.Equalf(t, want, paramNameTokens(in), "tokens of %q", in)
	}
}
