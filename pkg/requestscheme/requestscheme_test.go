package requestscheme

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/portsweep"
)

func rawFor(hostPort string, extra string) string {
	return "GET /x HTTP/1.1\r\nHost: " + hostPort + "\r\n" + extra + "\r\n"
}

func settle(t *testing.T, raw string, opts Options) Result {
	t.Helper()
	rr, err := httpmsg.ParseRawRequest(raw)
	require.NoError(t, err)
	return Settle(context.Background(), raw, rr, opts)
}

func TestSettleProbesPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	res := settle(t, rawFor(u.Host, ""), Options{})
	assert.Equal(t, SourceProbe, res.Source)
	assert.Equal(t, "http", res.Scheme)
	assert.True(t, res.Changed)
	assert.Equal(t, u.Host, res.ProbedAuthority)
	assert.Equal(t, "http://"+u.Host+"/x", res.Request.Target())
}

func TestSettleProbesTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	res := settle(t, rawFor(u.Host, ""), Options{})
	assert.Equal(t, SourceProbe, res.Source)
	assert.False(t, res.Changed)
	assert.Equal(t, "https://"+u.Host+"/x", res.Request.Target())
}

func TestSettleNothingAnsweredKeepsDefault(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host := l.Addr().String()
	_ = l.Close()

	res := settle(t, rawFor(host, ""), Options{})
	assert.Equal(t, SourceDefault, res.Source)
	assert.Equal(t, host, res.Authority)
	assert.True(t, res.ExplicitPort())
	assert.Equal(t, "https://"+host+"/x", res.Request.Target())
}

func TestSettleDecidesWithoutProbe(t *testing.T) {
	never := func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		t.Fatal("the target must not be probed")
		return portsweep.SchemeResolution{}
	}
	cases := []struct {
		name string
		raw  string
		opts Options
		want string
	}{
		{"pinned", rawFor("10.0.0.1:8080", ""), Options{Pinned: true}, SourceExplicit},
		{"absolute-form", "GET http://10.0.0.1:8080/x HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n", Options{}, SourceExplicit},
		{"port 80", rawFor("10.0.0.1:80", ""), Options{}, SourcePort},
		{"port 443", rawFor("10.0.0.1:443", ""), Options{}, SourcePort},
		{"origin", rawFor("10.0.0.1:8080", "Origin: http://10.0.0.1:8080\r\n"), Options{}, SourceOrigin},
		{"referer", rawFor("10.0.0.1:8080", "Referer: http://10.0.0.1:8080/a\r\n"), Options{}, SourceReferer},
		{"no probe", rawFor("10.0.0.1:8080", ""), Options{NoProbe: true}, SourceDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Resolver = never
			res := settle(t, tc.raw, tc.opts)
			assert.Equal(t, tc.want, res.Source)
			assert.False(t, res.Changed)
		})
	}

	// A curl command (raw == "") carries its URL.
	rr, err := httpmsg.GetRawRequestFromURL("http://10.0.0.1:8080/x")
	require.NoError(t, err)
	assert.Equal(t, SourceExplicit, Settle(context.Background(), "", rr, Options{Resolver: never}).Source)
}

func TestHostPort(t *testing.T) {
	h, p, ok := HostPort("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
	assert.True(t, ok)
	assert.Equal(t, "::1", h)
	assert.Equal(t, "8080", p)

	h, p, ok = HostPort("GET / HTTP/1.1\nhost: example.test\n\n")
	assert.True(t, ok)
	assert.Equal(t, "example.test", h)
	assert.Empty(t, p)

	_, _, ok = HostPort("GET / HTTP/1.1\r\n\r\n")
	assert.False(t, ok)
}
