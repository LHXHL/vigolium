package http

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
	"github.com/vigolium/vigolium/pkg/types"
)

// hostRecorder is a target on a random loopback port (never 80) that records
// the Host header of the last request it served.
func hostRecorder(t *testing.T) (addr string, lastHost func() string) {
	t.Helper()
	var (
		mu   sync.Mutex
		host string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		host = r.Host
		mu.Unlock()
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return host
	}
}

// scanRecord builds a scan record aimed at addr whose raw request carries
// hostHeader as its Host.
func scanRecord(t *testing.T, addr, path, hostHeader string) *httpmsg.HttpRequestResponse {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := httpmsg.NewService(h, port, "http")
	if err != nil {
		t.Fatal(err)
	}
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n"
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, []byte(raw)), nil)
}

func executeRecord(t *testing.T, r *Requester, rr *httpmsg.HttpRequestResponse) int {
	t.Helper()
	resp, _, err := r.Execute(rr, Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	defer resp.Close()
	if resp.Response() == nil {
		t.Fatal("no response")
	}
	return resp.Response().StatusCode
}

// TestScanRequestHostThroughHTTPProxy: the scanner sends a record's own Host
// header (a Host-header-injection probe, or a capture whose Host lacks the
// port). net/http names that Host in the absolute-form target it sends an HTTP
// proxy, so the proxy forwarded such a request to the Host's authority — port
// 80 of the target, or the injected host. The proxy must be asked for the
// record's real host:port, and the Host header must still arrive unchanged.
func TestScanRequestHostThroughHTTPProxy(t *testing.T) {
	addr, lastHost := hostRecorder(t)
	targetHost, _, _ := net.SplitHostPort(addr)
	proxy := proxytest.New(t)

	opts := types.DefaultOptions()
	opts.ProxyURL = proxy.URL.String()
	r := newTestRequesterWithOpts(t, opts)

	cases := []struct {
		name       string
		hostHeader string
	}{
		{"injected host", "evil.example"},
		{"host without port", targetHost},
		{"host with port", addr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(proxy.Hits())
			if code := executeRecord(t, r, scanRecord(t, addr, "/probe?x=1", tc.hostHeader)); code != http.StatusOK {
				t.Fatalf("status = %d, want 200 from the target through the proxy", code)
			}
			hits := proxy.Hits()[before:]
			if len(hits) != 1 {
				t.Fatalf("proxy saw %d requests, want 1", len(hits))
			}
			if want := "http://" + addr + "/probe?x=1"; hits[0].RequestTarget != want {
				t.Errorf("proxy request target = %q, want %q", hits[0].RequestTarget, want)
			}
			if hits[0].Host != tc.hostHeader {
				t.Errorf("proxy Host = %q, want %q", hits[0].Host, tc.hostHeader)
			}
			if got := lastHost(); got != tc.hostHeader {
				t.Errorf("target Host = %q, want %q", got, tc.hostHeader)
			}
		})
	}
}

// TestScanRequestHostDirect is the direct-connection control: the same records
// reach the right port and carry their Host header unchanged.
func TestScanRequestHostDirect(t *testing.T) {
	addr, lastHost := hostRecorder(t)
	targetHost, _, _ := net.SplitHostPort(addr)

	opts := types.DefaultOptions()
	opts.ProxyURL = ""
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	r := newTestRequesterWithOpts(t, opts)

	for _, hostHeader := range []string{"evil.example", targetHost, addr} {
		if code := executeRecord(t, r, scanRecord(t, addr, "/d", hostHeader)); code != http.StatusOK {
			t.Fatalf("Host %q: status = %d, want 200", hostHeader, code)
		}
		if got := lastHost(); got != hostHeader {
			t.Errorf("target Host = %q, want %q", got, hostHeader)
		}
	}
}

// TestLoginTransportHostOverrideThroughHTTPProxy: a login recipe may set its
// own Host header (pkg/authentication applies it as req.Host). Through an HTTP
// proxy the login must still be fetched from the login URL's host:port.
func TestLoginTransportHostOverrideThroughHTTPProxy(t *testing.T) {
	addr, lastHost := hostRecorder(t)
	proxy := proxytest.New(t)

	opts := types.DefaultOptions()
	opts.ProxyURL = proxy.URL.String()
	client := &http.Client{Transport: LoginTransport(opts)}

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.internal"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the target through the proxy", resp.StatusCode)
	}
	hits := proxy.Hits()
	if len(hits) != 1 || hits[0].RequestTarget != "http://"+addr+"/login" || hits[0].Host != "app.internal" {
		t.Errorf("proxy saw %+v, want target http://%s/login with Host app.internal", hits, addr)
	}
	if got := lastHost(); got != "app.internal" {
		t.Errorf("target Host = %q, want app.internal", got)
	}
}
