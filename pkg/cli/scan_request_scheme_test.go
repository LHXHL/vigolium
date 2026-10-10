package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/portsweep"
)

// scan-request scheme resolution: a raw request with no scheme signal (no -t,
// origin-form request line, non-standard port, no same-origin Origin/Referer)
// is probed instead of assumed https.

func a4RawRequest(hostPort string, extra ...string) string {
	return "GET /x HTTP/1.1\r\nHost: " + hostPort + "\r\n" + strings.Join(extra, "") + "\r\n"
}

func a4Settle(t *testing.T, raw string, pinned, noProbe bool) (*httpmsg.HttpRequestResponse, string) {
	t.Helper()
	normalized := normalizeRawRequestInput(raw)
	rr, err := httpmsg.ParseRawRequest(normalized)
	require.NoError(t, err)
	return settleRequestScheme(context.Background(), normalized, rr, pinned, noProbe)
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Host
}

// A plain-http service on a non-standard port resolves to http://.
func TestScanRequestSchemeProbePlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host := hostOf(t, srv.URL)

	rr, source := a4Settle(t, a4RawRequest(host), false, false)
	assert.Equal(t, schemeSourceProbe, source)
	assert.Equal(t, "http://"+host+"/x", rr.Target())
	assert.Equal(t, "http://"+host, resolvedTargetOf(rr))
}

// A TLS service on a non-standard port stays https://, now by probe.
func TestScanRequestSchemeProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host := hostOf(t, srv.URL)

	rr, source := a4Settle(t, a4RawRequest(host), false, false)
	assert.Equal(t, schemeSourceProbe, source)
	assert.Equal(t, "https://"+host+"/x", rr.Target())
}

// Nothing answered: the inferred https default is kept and labelled default,
// and the hint names the -t fix.
func TestScanRequestSchemeProbeNothingAnswered(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host := l.Addr().String()
	_ = l.Close()

	rr, source := a4Settle(t, a4RawRequest(host), false, false)
	assert.Equal(t, schemeSourceDefault, source)
	assert.True(t, strings.HasPrefix(rr.Target(), "https://"), rr.Target())
	assert.Contains(t, schemeHint(source, resolvedTargetOf(rr)), "-t http://"+host)
}

// Signals in the request decide without a probe: -t, an absolute-form request
// line, a well-known port, a same-origin Origin/Referer, and --no-scheme-probe.
func TestScanRequestSchemeNoProbe(t *testing.T) {
	orig := requestSchemeResolver
	t.Cleanup(func() { requestSchemeResolver = orig })
	requestSchemeResolver = func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		t.Fatal("the target must not be probed")
		return portsweep.SchemeResolution{}
	}

	cases := []struct {
		name    string
		raw     string
		pinned  bool
		noProbe bool
		want    string
	}{
		{"-t override", a4RawRequest("10.0.0.1:8080"), true, false, schemeSourceExplicit},
		{"absolute-form", "GET http://10.0.0.1:8080/x HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n", false, false, schemeSourceExplicit},
		{"port 80", a4RawRequest("10.0.0.1:80"), false, false, schemeSourcePort},
		{"port 443", a4RawRequest("10.0.0.1:443"), false, false, schemeSourcePort},
		{"origin", a4RawRequest("10.0.0.1:8080", "Origin: http://10.0.0.1:8080\r\n"), false, false, schemeSourceOrigin},
		{"referer", a4RawRequest("10.0.0.1:8080", "Referer: http://10.0.0.1:8080/a\r\n"), false, false, schemeSourceReferer},
		{"--no-scheme-probe", a4RawRequest("10.0.0.1:8080"), false, true, schemeSourceDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, source := a4Settle(t, tc.raw, tc.pinned, tc.noProbe)
			assert.Equal(t, tc.want, source)
		})
	}

	// A curl command carries its URL; normalized is empty for it.
	rr, err := httpmsg.GetRawRequestFromURL("http://10.0.0.1:8080/x")
	require.NoError(t, err)
	_, source := settleRequestScheme(context.Background(), "", rr, false, false)
	assert.Equal(t, schemeSourceExplicit, source)
}
