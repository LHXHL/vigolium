package modtest

import "testing"

// TestExchangeBuildersRaw pins the exact bytes the builders produce, so the
// passive tests migrated off private makeHTTPCtx copies keep their fixtures.
func TestExchangeBuildersRaw(t *testing.T) {
	cases := []struct {
		name          string
		gotReq, gotRs string
		wantReq       string
		wantRs        string
	}{
		{
			name:    "HTTPCtx",
			gotReq:  string(HTTPCtx("/a?b=1", "text/html", "<p>").Request().Raw()),
			gotRs:   string(HTTPCtx("/a?b=1", "text/html", "<p>").Response().Raw()),
			wantReq: "GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantRs:  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>",
		},
		{
			name:    "HTTPCtxMethod",
			gotReq:  string(HTTPCtxMethod("POST", "/graphql", "application/json", "{}").Request().Raw()),
			gotRs:   string(HTTPCtxMethod("POST", "/graphql", "application/json", "{}").Response().Raw()),
			wantReq: "POST /graphql HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantRs:  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
		},
		{
			name:    "HTTPCtxHeaders",
			gotReq:  string(HTTPCtxHeaders("/", "Server: x\r\n", "ok").Request().Raw()),
			gotRs:   string(HTTPCtxHeaders("/", "Server: x\r\n", "ok").Response().Raw()),
			wantReq: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantRs:  "HTTP/1.1 200 OK\r\nServer: x\r\n\r\nok",
		},
	}
	for _, c := range cases {
		if c.gotReq != c.wantReq {
			t.Errorf("%s request = %q, want %q", c.name, c.gotReq, c.wantReq)
		}
		if c.gotRs != c.wantRs {
			t.Errorf("%s response = %q, want %q", c.name, c.gotRs, c.wantRs)
		}
	}
	rr := RawCtx("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n")
	if svc := rr.Request().Service(); svc == nil || svc.Host() != "example.com" || svc.Port() != 443 || svc.Protocol() != "https" {
		t.Errorf("RawCtx service = %+v, want https example.com:443", svc)
	}
}
