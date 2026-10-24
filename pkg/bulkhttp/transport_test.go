package bulkhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// origin under test: a TLS TCP server (HTTP/2 when h2) and, when h3, an
// HTTP/3 server on the same port number over UDP, both answering
// "<proto-major> <path>".
type testOrigin struct {
	URL      *url.URL
	tcp      *httptest.Server
	h3       *http3.Server
	requests atomic.Int64
	tcpConns atomic.Int64
	h3Conns  sync.Map // remote addr -> struct{}
}

func startOrigin(t testing.TB, h2, h3 bool, handler http.HandlerFunc) *testOrigin {
	t.Helper()
	o := &testOrigin{}
	h := func(w http.ResponseWriter, r *http.Request) {
		o.requests.Add(1)
		if r.ProtoMajor == 3 {
			o.h3Conns.Store(r.RemoteAddr, struct{}{})
		}
		if handler != nil {
			handler(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, "%d %s", r.ProtoMajor, r.URL.Path)
	}
	o.tcp = httptest.NewUnstartedServer(http.HandlerFunc(h))
	o.tcp.EnableHTTP2 = h2
	o.tcp.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			o.tcpConns.Add(1)
		}
	}
	o.tcp.StartTLS()
	t.Cleanup(o.tcp.Close)
	o.URL, _ = url.Parse(o.tcp.URL)

	if h3 {
		_, port, _ := net.SplitHostPort(o.tcp.Listener.Addr().String())
		p, _ := strconv.Atoi(port)
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err != nil {
			t.Skipf("cannot bind UDP port %d for the HTTP/3 origin: %v", p, err)
		}
		o.h3 = &http3.Server{
			Handler:   http.HandlerFunc(h),
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: o.tcp.TLS.Certificates}),
		}
		go func() { _ = o.h3.Serve(pc) }()
		t.Cleanup(func() { _ = o.h3.Close(); _ = pc.Close() })
	}
	return o
}

func (o *testOrigin) h3ConnCount() int {
	n := 0
	o.h3Conns.Range(func(any, any) bool { n++; return true })
	return n
}

// newTestBase is the HTTP/1.1 template the tests build Transports from.
func newTestBase() *http.Transport {
	return &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test origin
		MaxIdleConnsPerHost: 64,
	}
}

func newTestTransport(t *testing.T, mode Mode, tweak func(*Config)) *Transport {
	t.Helper()
	cfg := Config{
		Base:         newTestBase(),
		Mode:         mode,
		ProbeTimeout: 500 * time.Millisecond,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	tr := New(cfg)
	t.Cleanup(tr.Close)
	return tr
}

func get(t *testing.T, tr http.RoundTripper, u string, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestAutoPinsEachOriginToItsBestProtocol(t *testing.T) {
	cases := []struct {
		name      string
		h2, h3    bool
		mode      Mode
		wantMajor int
		wantProto Protocol
	}{
		{"h3 origin under auto", true, true, ModeAuto, 3, ProtoHTTP3},
		{"h2-only origin under auto", true, false, ModeAuto, 2, ProtoHTTP2},
		{"h1-only origin under auto", false, false, ModeAuto, 1, ProtoHTTP1},
		{"h3 origin under http2 mode", true, true, ModeHTTP2, 2, ProtoHTTP2},
		{"h3 origin under http1 mode", true, true, ModeHTTP1, 1, ProtoHTTP1},
		{"h3 origin under http3 mode", true, true, ModeHTTP3, 3, ProtoHTTP3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := startOrigin(t, tc.h2, tc.h3, nil)
			tr := newTestTransport(t, tc.mode, nil)
			for i := 0; i < 3; i++ {
				resp, body := get(t, tr, o.URL.String()+"/p"+strconv.Itoa(i), nil)
				if resp.ProtoMajor != tc.wantMajor {
					t.Fatalf("request %d used HTTP/%d (%q), want HTTP/%d", i, resp.ProtoMajor, body, tc.wantMajor)
				}
				if want := fmt.Sprintf("%d /p%d", tc.wantMajor, i); body != want {
					t.Errorf("body = %q, want %q", body, want)
				}
			}
			if got := tr.Protocol(o.URL); got != tc.wantProto {
				t.Errorf("Protocol = %q, want %q", got, tc.wantProto)
			}
		})
	}
}

// HTTP/3 required on an origin without it fails instead of falling back.
func TestHTTP3ModeFailsWithoutHTTP3(t *testing.T) {
	o := startOrigin(t, true, false, nil)
	tr := newTestTransport(t, ModeHTTP3, nil)
	req, _ := http.NewRequest(http.MethodGet, o.URL.String(), nil)
	if resp, err := tr.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 mode fell back to HTTP/%d", resp.ProtoMajor)
	}
	if n := o.requests.Load(); n != 0 {
		t.Errorf("origin saw %d requests, want 0", n)
	}
	if _, err := tr.Prepare(context.Background(), o.URL); err == nil {
		t.Error("Prepare succeeded in HTTP/3 mode without HTTP/3")
	}
}

// A connection-specific header is meaningless (and silently dropped) on
// HTTP/2 and HTTP/3, so such a request goes over HTTP/1.1 even to an h3 origin.
func TestConnectionSpecificHeadersStayOnHTTP1(t *testing.T) {
	var gotUpgrade atomic.Value
	o := startOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Probe") == "1" {
			gotUpgrade.Store(r.Header.Get("Upgrade"))
		}
		_, _ = fmt.Fprintf(w, "%d", r.ProtoMajor)
	})
	tr := newTestTransport(t, ModeAuto, nil)
	if resp, _ := get(t, tr, o.URL.String(), nil); resp.ProtoMajor != 3 {
		t.Fatalf("plain request used HTTP/%d, want 3", resp.ProtoMajor)
	}
	resp, _ := get(t, tr, o.URL.String(), http.Header{"Upgrade": {"vigolium-test"}, "X-Probe": {"1"}})
	if resp.ProtoMajor != 1 {
		t.Errorf("request with Upgrade used HTTP/%d, want 1", resp.ProtoMajor)
	}
	if got, _ := gotUpgrade.Load().(string); got != "vigolium-test" {
		t.Errorf("server saw Upgrade %q, want it delivered", got)
	}
}

func TestRequiresHTTP1(t *testing.T) {
	cases := []struct {
		h    http.Header
		want bool
	}{
		{http.Header{"Accept": {"*/*"}}, false},
		{http.Header{"Te": {"trailers"}}, false},
		{http.Header{"Te": {"gzip"}}, true},
		// Pure HTTP/1.x connection management: dropped harmlessly.
		{http.Header{"Connection": {"close"}}, false},
		{http.Header{"Connection": {"Keep-Alive"}}, false},
		{http.Header{"keep-alive": {"timeout=5"}}, false},
		{http.Header{"Proxy-Connection": {"keep-alive"}}, false},
		// Meaningful: a nominated hop-by-hop header, a protocol switch, framing.
		{http.Header{"Connection": {"keep-alive, X-Forwarded-For"}}, true},
		{http.Header{"Transfer-Encoding": {"chunked"}}, true},
		{http.Header{"Upgrade": {"websocket"}}, true},
	}
	for _, tc := range cases {
		if got := RequiresHTTP1(tc.h) != ""; got != tc.want {
			t.Errorf("RequiresHTTP1(%v) = %v, want %v", tc.h, got, tc.want)
		}
	}
}

// Many concurrent requests spread over several HTTP/3 connections, never more
// than MaxH3Conns, and every slot is returned once bodies are closed.
func TestHTTP3PoolGrowsAndDrains(t *testing.T) {
	o := startOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	})
	tr := newTestTransport(t, ModeAuto, func(c *Config) {
		c.StreamsPerConn = 20
		c.MaxH3Conns = 4
	})
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}

	const n = 200
	var wg sync.WaitGroup
	var failed atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(o.URL.String() + "/c" + strconv.Itoa(i))
			if err != nil {
				failed.Add(1)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.ProtoMajor != 3 {
				failed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if f := failed.Load(); f != 0 {
		t.Fatalf("%d of %d requests failed or left HTTP/3", f, n)
	}
	if c := o.h3ConnCount(); c < 2 || c > 4 {
		t.Errorf("origin saw %d HTTP/3 connections, want 2..4 (grown past one, capped at MaxH3Conns)", c)
	}
	v, _ := tr.origins.Load(originKey(o.URL))
	pool := v.(*origin).pool
	if held := len(pool.tokens); held != 0 {
		t.Errorf("%d stream slots still held after every body was closed", held)
	}
}

// An origin whose HTTP/3 side goes away keeps working: requests fail over to
// TCP and the origin is demoted rather than the scan stalling.
func TestHTTP3OriginDemotesToTCPWhenItsQUICSideDies(t *testing.T) {
	o := startOrigin(t, true, true, nil)
	tr := newTestTransport(t, ModeAuto, nil)
	if resp, _ := get(t, tr, o.URL.String(), nil); resp.ProtoMajor != 3 {
		t.Fatalf("first request used HTTP/%d, want 3", resp.ProtoMajor)
	}
	_ = o.h3.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, o.URL.String(), nil)
		resp, err := (&http.Client{Transport: tr, Timeout: 15 * time.Second}).Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.ProtoMajor == 2 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("never failed over to TCP (last err %v)", err)
		}
	}
	if got := tr.Protocol(o.URL); got != ProtoHTTP2 {
		t.Errorf("Protocol after demotion = %q, want h2", got)
	}
}

// Prepare decides the protocol without sending an HTTP request.
func TestPrepareSendsNoRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		h2, h3 bool
		want   Protocol
	}{
		{"h3", true, true, ProtoHTTP3},
		{"h2", true, false, ProtoHTTP2},
		{"h1", false, false, ProtoHTTP1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := startOrigin(t, tc.h2, tc.h3, nil)
			tr := newTestTransport(t, ModeAuto, nil)
			got, err := tr.Prepare(context.Background(), o.URL)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Prepare = %q, want %q", got, tc.want)
			}
			if n := o.requests.Load(); n != 0 {
				t.Errorf("Prepare sent %d HTTP requests, want 0", n)
			}
		})
	}
}

func TestH3IneligibleReasons(t *testing.T) {
	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	cases := []struct {
		name   string
		mode   Mode
		target string
		proxy  bool
		want   bool // eligible
	}{
		{"https direct auto", ModeAuto, "https://a.test/", false, true},
		{"cleartext", ModeAuto, "http://a.test/", false, false},
		{"proxied", ModeAuto, "https://a.test/", true, false},
		{"http2 mode", ModeHTTP2, "https://a.test/", false, false},
		{"http1 mode", ModeHTTP1, "https://a.test/", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := &http.Transport{}
			if tc.proxy {
				base.Proxy = http.ProxyURL(proxyURL)
			}
			tr := New(Config{Base: base, Mode: tc.mode})
			defer tr.Close()
			req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			if got := tr.h3Ineligible(req) == ""; got != tc.want {
				t.Errorf("eligible = %v, want %v (reason %q)", got, tc.want, tr.h3Ineligible(req))
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{
		"": ModeAuto, "auto": ModeAuto, "1.1": ModeHTTP1, "http1": ModeHTTP1,
		"h2": ModeHTTP2, "HTTP2": ModeHTTP2, "3": ModeHTTP3, "http3": ModeHTTP3,
	} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMode("spdy"); err == nil {
		t.Error("ParseMode accepted spdy")
	}
}

// An origin without HTTP/3 must not cost the full ProbeTimeout: the racing
// TCP handshake cuts the QUIC probe short once it has had as long again.
func TestProbeGivesUpSoonAfterTCPAnswers(t *testing.T) {
	o := startOrigin(t, true, false, nil)
	tr := newTestTransport(t, ModeAuto, func(c *Config) { c.ProbeTimeout = 10 * time.Second })
	start := time.Now()
	got, err := tr.Prepare(context.Background(), o.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != ProtoHTTP2 {
		t.Errorf("Prepare = %q, want h2", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("deciding a non-HTTP/3 origin took %v, want well under the 10s ProbeTimeout", elapsed)
	}
}

// connUnusableText must match quic-go's wording for a request that never got
// a stream, or GOAWAY retirement and unsent retries silently stop working.
func TestConnUnusableText(t *testing.T) {
	o := startOrigin(t, true, true, nil)
	tr := newTestTransport(t, ModeHTTP3, nil)
	if resp, _ := get(t, tr, o.URL.String(), nil); resp.ProtoMajor != 3 {
		t.Fatalf("setup request used HTTP/%d, want 3", resp.ProtoMajor)
	}
	v, _ := tr.origins.Load(originKey(o.URL))
	pool := v.(*origin).pool
	pool.mu.Lock()
	c := pool.conns[0]
	pool.mu.Unlock()
	_ = c.qc.CloseWithError(0, "")
	<-c.qc.Context().Done()

	req, _ := http.NewRequest(http.MethodGet, o.URL.String(), nil)
	_, err := c.cc.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), connUnusableText) {
		t.Fatalf("RoundTrip on a closed connection = %v, want an error containing %q", err, connUnusableText)
	}
}
