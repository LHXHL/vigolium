package proxytarget

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
)

type hit struct {
	requestURI string
	host       string
}

// forwardProxy starts a recording forward proxy (see proxytest) and returns its
// URL and an accessor for what it received.
func forwardProxy(t *testing.T) (*url.URL, func() []hit) {
	t.Helper()
	p := proxytest.New(t)
	return p.URL, func() []hit {
		var out []hit
		for _, h := range p.Hits() {
			out = append(out, hit{requestURI: h.RequestTarget, host: h.Host})
		}
		return out
	}
}

// target answers on a random loopback port and records the Host and request
// target it received.
func target(t *testing.T) (string, func() hit) {
	t.Helper()
	var (
		mu   sync.Mutex
		last hit
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = hit{requestURI: r.RequestURI, host: r.Host}
		mu.Unlock()
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), func() hit {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func get(t *testing.T, rt http.RoundTripper, rawURL, hostHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHostOverrideThroughHTTPProxy is the case net/http gets wrong on its own:
// the Host header names another host (or drops the port), and the proxy must
// still be asked to fetch the URL's host:port.
func TestHostOverrideThroughHTTPProxy(t *testing.T) {
	addr, seen := target(t)
	host, _, _ := net.SplitHostPort(addr)
	px, hits := forwardProxy(t)

	cases := []struct {
		name       string
		hostHeader string
	}{
		{"injected host", "evil.example"},
		{"host without port", host},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(hits())
			tr := Wrap(&http.Transport{Proxy: http.ProxyURL(px)})
			defer tr.CloseIdleConnections()

			resp := get(t, tr, "http://"+addr+"/a/..%2fadmin?q=1", tc.hostHeader)
			if resp.StatusCode != http.StatusOK || readBody(t, resp) != "target-ok" {
				t.Fatalf("request did not reach the target: status %d", resp.StatusCode)
			}
			got := hits()[before:]
			if len(got) != 1 {
				t.Fatalf("proxy saw %d requests, want 1", len(got))
			}
			if want := "http://" + addr + "/a/..%2fadmin?q=1"; got[0].requestURI != want {
				t.Errorf("proxy request target = %q, want %q", got[0].requestURI, want)
			}
			if got[0].host != tc.hostHeader {
				t.Errorf("proxy Host = %q, want %q", got[0].host, tc.hostHeader)
			}
			if s := seen(); s.host != tc.hostHeader || s.requestURI != "/a/..%2fadmin?q=1" {
				t.Errorf("target saw %+v, want Host %q and the escaped path", s, tc.hostHeader)
			}
		})
	}
}

// TestUnwrappedTransportRoutesToHostHeader documents the net/http behavior the
// package exists for, so a Go release that changes it is noticed.
func TestUnwrappedTransportRoutesToHostHeader(t *testing.T) {
	addr, _ := target(t)
	host, _, _ := net.SplitHostPort(addr)
	px, hits := forwardProxy(t)

	tr := &http.Transport{Proxy: http.ProxyURL(px)}
	defer tr.CloseIdleConnections()
	resp := get(t, tr, "http://"+addr+"/x", host)
	_ = readBody(t, resp)
	got := hits()
	if len(got) != 1 {
		t.Fatalf("proxy saw %d requests, want 1", len(got))
	}
	if got[0].requestURI != "http://"+host+"/x" {
		t.Skipf("net/http now writes %q for the proxy target; proxytarget may be unnecessary", got[0].requestURI)
	}
}

// TestUnchangedRequests covers every request the wrapper must leave alone.
func TestUnchangedRequests(t *testing.T) {
	addr, seen := target(t)
	px, hits := forwardProxy(t)

	t.Run("direct connection keeps the override and origin form", func(t *testing.T) {
		tr := Wrap(&http.Transport{})
		defer tr.CloseIdleConnections()
		resp := get(t, tr, "http://"+addr+"/d", "vhost.example")
		if readBody(t, resp) != "target-ok" {
			t.Fatal("direct request did not reach the target")
		}
		if s := seen(); s.requestURI != "/d" || s.host != "vhost.example" {
			t.Errorf("target saw %+v, want origin-form /d with Host vhost.example", s)
		}
	})

	t.Run("matching host through the proxy", func(t *testing.T) {
		before := len(hits())
		tr := Wrap(&http.Transport{Proxy: http.ProxyURL(px)})
		defer tr.CloseIdleConnections()
		_ = readBody(t, get(t, tr, "http://"+addr+"/m", ""))
		got := hits()[before:]
		if len(got) != 1 || got[0].requestURI != "http://"+addr+"/m" || got[0].host != addr {
			t.Errorf("proxy saw %+v, want target http://%s/m with Host %s", got, addr, addr)
		}
	})

	t.Run("proxy func declines the request", func(t *testing.T) {
		before := len(hits())
		tr := Wrap(&http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }})
		defer tr.CloseIdleConnections()
		_ = readBody(t, get(t, tr, "http://"+addr+"/n", "vhost.example"))
		if len(hits()) != before {
			t.Error("request went through the proxy although Proxy returned nil")
		}
		if s := seen(); s.requestURI != "/n" || s.host != "vhost.example" {
			t.Errorf("target saw %+v, want origin-form /n with Host vhost.example", s)
		}
	})
}

func TestNeedsAbsoluteTarget(t *testing.T) {
	httpProxy := func(*http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:8080") }
	socksProxy := func(*http.Request) (*url.URL, error) { return url.Parse("socks5://127.0.0.1:1080") }
	httpsProxy := func(*http.Request) (*url.URL, error) { return url.Parse("https://proxy.example:8443") }

	cases := []struct {
		name  string
		proxy func(*http.Request) (*url.URL, error)
		url   string
		host  string
		want  bool
	}{
		{"http proxy, override", httpProxy, "http://t.example:8080/x", "evil.example", true},
		{"https proxy, override", httpsProxy, "http://t.example:8080/x", "evil.example", true},
		{"http proxy, same host", httpProxy, "http://t.example:8080/x", "t.example:8080", false},
		{"http proxy, empty host", httpProxy, "http://t.example:8080/x", "", false},
		{"socks proxy", socksProxy, "http://t.example:8080/x", "evil.example", false},
		{"https target is tunnelled", httpProxy, "https://t.example:8443/x", "evil.example", false},
		{"no proxy", nil, "http://t.example:8080/x", "evil.example", false},
		{"ipv6 zone", httpProxy, "http://[fe80::1%25en0]:8080/x", "evil.example", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			tr := Wrap(&http.Transport{Proxy: tc.proxy})
			if got := tr.needsAbsoluteTarget(req); got != tc.want {
				t.Errorf("needsAbsoluteTarget = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWithAbsoluteTargetLeavesCallerRequestAlone(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://t.example:8080", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example"
	out := withAbsoluteTarget(req)
	if got := out.URL.RequestURI(); got != "http://t.example:8080/" {
		t.Errorf("request target = %q, want http://t.example:8080/", got)
	}
	if req.URL.Opaque != "" {
		t.Error("caller's request was modified")
	}
	if out.Host != "evil.example" {
		t.Errorf("Host = %q, want the override", out.Host)
	}
}

func TestBase(t *testing.T) {
	plain := &http.Transport{}
	if got, ok := Base(plain); !ok || got != plain {
		t.Error("Base(*http.Transport) should return it")
	}
	if got, ok := Base(Wrap(plain)); !ok || got != plain {
		t.Error("Base(*Transport) should return the embedded transport")
	}
	if _, ok := Base(http.RoundTripper(nil)); ok {
		t.Error("Base(nil) should report false")
	}
	other := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	if _, ok := Base(other); ok {
		t.Error("Base(other RoundTripper) should report false")
	}
	if Wrap(nil).Transport == nil {
		t.Error("Wrap(nil) should supply a transport")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
