package modtest

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Captured-exchange fixtures for passive-module tests. A passive module only
// reads an already-captured request/response pair, so these builders need no
// server and no *testing.T: every exchange targets https://example.com:443 and
// the response is attached as given.
//
// Pick the narrowest builder that fits; fall back to RawCtx for a hand-written
// request or response (custom status line, request headers, binary body).

// fixtureHost is the host every captured-exchange fixture targets.
const fixtureHost = "example.com"

// RawCtx pairs the raw request rawReq, addressed to https://example.com:443,
// with the raw response rawResp.
func RawCtx(rawReq, rawResp string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(fixtureHost, 443, true),
		[]byte(rawReq),
	)
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

// HTTPCtx builds a captured GET of path (request-target, may carry a query)
// answered by a 200 OK with the given Content-Type and body.
func HTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	return HTTPCtxMethod("GET", path, contentType, body)
}

// HTTPCtxMethod is HTTPCtx with an explicit request method.
func HTTPCtxMethod(method, path, contentType, body string) *httpmsg.HttpRequestResponse {
	return RawCtx(
		requestHead(method, path),
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body),
	)
}

// HTTPCtxHeaders builds a captured GET of path answered by a 200 OK whose
// header block is headers verbatim. Each header line in headers must end in
// "\r\n" (an empty string means no headers); the blank line and body follow.
func HTTPCtxHeaders(path, headers, body string) *httpmsg.HttpRequestResponse {
	return RawCtx(requestHead("GET", path), "HTTP/1.1 200 OK\r\n"+headers+"\r\n"+body)
}

// requestHead is a header-only request for method and path on fixtureHost.
func requestHead(method, path string) string {
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, fixtureHost)
}
