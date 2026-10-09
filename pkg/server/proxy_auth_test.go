package server

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
)

const testProxyToken = "s3cret-proxy-token"

// upstreamRecorder is an origin that remembers the Proxy-Authorization it saw.
type upstreamRecorder struct {
	mu       sync.Mutex
	seenAuth []string
}

func (u *upstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seenAuth = append(u.seenAuth, r.Header.Get("Proxy-Authorization"))
		u.mu.Unlock()
		_, _ = io.WriteString(w, "origin-ok")
	})
}

func (u *upstreamRecorder) leaked() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, a := range u.seenAuth {
		if a != "" {
			return true
		}
	}
	return false
}

// authedProxy starts an ingest proxy (no DB, no MITM) gated by auth.
func authedProxy(t *testing.T, auth *ProxyAuth) *url.URL {
	t.Helper()
	srv := newIngestProxy("127.0.0.1:0", nil, nil, nil, nil,
		func() *config.ScopeMatcher { return nil }, nil, false, auth)
	pu, err := url.Parse(startProxy(t, srv))
	require.NoError(t, err)
	return pu
}

func proxyClient(proxyURL *url.URL, connectHeader http.Header) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(proxyURL),
		ProxyConnectHeader: connectHeader,
		// #nosec G402 -- local httptest TLS origin
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func withUser(u *url.URL, user *url.Userinfo) *url.URL {
	c := *u
	c.User = user
	return &c
}

func TestIngestProxyAuth_PlainHTTP(t *testing.T) {
	rec := &upstreamRecorder{}
	origin := httptest.NewServer(rec.handler())
	defer origin.Close()
	pu := authedProxy(t, &ProxyAuth{Token: testProxyToken})

	t.Run("no credential is 407 with a challenge", func(t *testing.T) {
		resp, err := proxyClient(pu, nil).Get(origin.URL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
		assert.Equal(t, `Basic realm="vigolium"`, resp.Header.Get("Proxy-Authenticate"))
	})

	t.Run("wrong token is 407", func(t *testing.T) {
		resp, err := proxyClient(withUser(pu, url.UserPassword("x", "nope")), nil).Get(origin.URL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
	})

	t.Run("basic with any username passes", func(t *testing.T) {
		resp, err := proxyClient(withUser(pu, url.UserPassword("anyone", testProxyToken)), nil).Get(origin.URL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "origin-ok", string(body))
	})

	t.Run("bearer passes", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+testProxyToken)
		resp, err := proxyClient(pu, nil).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	assert.False(t, rec.leaked(), "Proxy-Authorization must be stripped before forwarding")
}

func TestIngestProxyAuth_Connect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls-origin-ok")
	}))
	defer origin.Close()
	pu := authedProxy(t, &ProxyAuth{Token: testProxyToken})

	_, err := proxyClient(pu, nil).Get(origin.URL)
	require.Error(t, err, "CONNECT without a credential must be refused")
	assert.Contains(t, err.Error(), "Proxy Authentication Required")

	resp, err := proxyClient(withUser(pu, url.UserPassword("", testProxyToken)), nil).Get(origin.URL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "tls-origin-ok", string(body))

	resp, err = proxyClient(pu, http.Header{"Proxy-Authorization": {"Bearer " + testProxyToken}}).Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIngestProxyAuth_AllowList(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	deny, err := NewProxyAuth("", []string{"10.0.0.0/8"})
	require.NoError(t, err)
	resp, err := proxyClient(authedProxy(t, deny), nil).Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "127.0.0.1 is outside 10.0.0.0/8")

	allow, err := NewProxyAuth("", []string{"127.0.0.0/8"})
	require.NoError(t, err)
	resp, err = proxyClient(authedProxy(t, allow), nil).Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Both configured: an allowed client still owes the token.
	both, err := NewProxyAuth(testProxyToken, []string{"127.0.0.1"})
	require.NoError(t, err)
	resp, err = proxyClient(authedProxy(t, both), nil).Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
}

func TestProxyCredential(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := map[string]string{
		"Bearer tok":                   "tok",
		"bearer  tok ":                 "tok",
		"Basic " + b64("user:tok"):     "tok",
		"Basic " + b64(":tok"):         "tok",
		"Basic " + b64("tok"):          "tok",
		"Basic " + b64("u:p:with:col"): "p:with:col",
		"Basic !!!notbase64":           "",
		"Digest abc":                   "",
		"":                             "",
		"Bearer":                       "",
	}
	for header, want := range cases {
		assert.Equal(t, want, proxyCredential(header), "header %q", header)
	}
	assert.False(t, tokenMatches("", ""), "an empty credential never matches")
	assert.True(t, tokenMatches("abc", "abc"))
	assert.False(t, tokenMatches("abc", "abcd"))
}

func TestCheckProxyBind(t *testing.T) {
	open := &ProxyAuth{}
	tokened := &ProxyAuth{Token: "x"}
	allowed, err := NewProxyAuth("", []string{"10.1.2.3"})
	require.NoError(t, err)

	for _, host := range []string{"127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"} {
		assert.NoError(t, CheckProxyBind(host, open), host)
		assert.NoError(t, CheckProxyBind(host, nil), host)
	}
	for _, host := range []string{"0.0.0.0", "", "::", "192.168.1.10", "proxy.internal"} {
		err := CheckProxyBind(host, open)
		require.Error(t, err, host)
		assert.Contains(t, err.Error(), "--proxy-token")
		assert.NoError(t, CheckProxyBind(host, tokened), host)
		assert.NoError(t, CheckProxyBind(host, allowed), host)
	}
}

func TestParseProxyAllow(t *testing.T) {
	nets, err := ParseProxyAllow([]string{"10.0.0.0/8", " 192.168.1.5 ", "", "::1", "fd00::/8"})
	require.NoError(t, err)
	require.Len(t, nets, 4)
	assert.Equal(t, "192.168.1.5/32", nets[1].String())
	assert.Equal(t, "::1/128", nets[2].String())

	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0/8"} {
		_, err := ParseProxyAllow([]string{bad})
		require.Error(t, err, bad)
		assert.True(t, strings.Contains(err.Error(), "--proxy-allow"), bad)
	}
}

func TestProxyAuthMode(t *testing.T) {
	assert.Equal(t, "none", proxyAuthMode(nil))
	assert.Equal(t, "token", proxyAuthMode(&ProxyAuth{Token: "x"}))
	a, _ := NewProxyAuth("", []string{"10.0.0.0/8"})
	assert.Equal(t, "allowlist", proxyAuthMode(a))
	a.Token = "x"
	assert.Equal(t, "token+allowlist", proxyAuthMode(a))
}
