package h2race

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/vigolium/vigolium/pkg/http/h2race/h2racetest"
)

// newH2Server starts a TLS httptest server speaking HTTP/2 through
// golang.org/x/net/http2's server.
func newH2Server(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	require.NoError(t, http2.ConfigureServer(ts.Config, &http2.Server{}))
	ts.TLS = ts.Config.TLSConfig
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func targetOf(t *testing.T, rawURL string) Target {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	return Target{Host: u.Hostname(), Port: port, TLS: u.Scheme == "https"}
}

func post(authority, path, body string) Request {
	return Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: authority,
		Path:      path,
		Header:    []Header{{Name: "content-type", Value: "text/plain"}},
		Body:      []byte(body),
	}
}

// arrivals records, per request, when the handler started (HEADERS) and when
// its body finished (END_STREAM).
type arrivals struct {
	mu       sync.Mutex
	started  []time.Time
	finished []time.Time
}

func (a *arrivals) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.started = append(a.started, time.Now())
		a.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.finished = append(a.finished, time.Now())
		a.mu.Unlock()
		w.Header().Set("X-Proto", r.Proto)
		_, _ = w.Write([]byte("echo:" + string(body)))
	}
}

func spread(ts []time.Time) (first, last time.Time) {
	first, last = ts[0], ts[0]
	for _, x := range ts[1:] {
		if x.Before(first) {
			first = x
		}
		if x.After(last) {
			last = x
		}
	}
	return first, last
}

func TestSinglePacket_WithholdsThenReleasesTogether(t *testing.T) {
	var a arrivals
	ts := newH2Server(t, a.handler())
	tg := targetOf(t, ts.URL)

	const n = 6
	const settle = 250 * time.Millisecond
	reqs := make([]Request, n)
	for i := range reqs {
		reqs[i] = post(ts.Listener.Addr().String(), "/redeem", "code=ABC"+strconv.Itoa(i))
	}
	resps, err := SinglePacket(context.Background(), tg, reqs, Options{Timeout: 5 * time.Second, Settle: settle})
	require.NoError(t, err)
	require.Len(t, resps, n)
	for i, r := range resps {
		require.NoError(t, r.Err, "stream %d", i)
		assert.Equal(t, 200, r.Status)
		assert.Equal(t, "HTTP/2.0", r.Proto)
		assert.Equal(t, "HTTP/2.0", r.Header.Get("X-Proto"))
		assert.Equal(t, "echo:code=ABC"+strconv.Itoa(i), string(r.Body), "responses stay index-aligned")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.finished, n)
	_, lastStart := spread(a.started)
	firstEnd, lastEnd := spread(a.finished)
	// The bodies were held back for the settle period after every request's
	// HEADERS had arrived...
	assert.GreaterOrEqual(t, firstEnd.Sub(lastStart), settle-50*time.Millisecond,
		"END_STREAM must be withheld until the release")
	// ...and then all completed together.
	assert.Less(t, lastEnd.Sub(firstEnd), 50*time.Millisecond, "final frames must arrive together")
}

func TestFinalBatch_OneEndStreamDataFramePerStream(t *testing.T) {
	reqs := []Request{post("h", "/", "abc"), post("h", "/", ""), post("h", "/", "z")}
	streams := []*h2stream{{id: 1}, {id: 3}, {id: 5}}
	batch, err := finalBatch(reqs, streams)
	require.NoError(t, err)

	fr := http2.NewFramer(nil, bytes.NewReader(batch))
	want := []struct {
		id   uint32
		data string
	}{{1, "c"}, {3, ""}, {5, "z"}}
	for _, w := range want {
		f, err := fr.ReadFrame()
		require.NoError(t, err)
		df, ok := f.(*http2.DataFrame)
		require.True(t, ok, "frame %T", f)
		assert.Equal(t, w.id, df.StreamID)
		assert.True(t, df.StreamEnded())
		assert.Equal(t, w.data, string(df.Data()))
	}
	_, err = fr.ReadFrame()
	assert.ErrorIs(t, err, io.EOF, "nothing but the final DATA frames")
}

func TestSinglePacket_EmitsConflictingFramingHeaders(t *testing.T) {
	srv := h2racetest.NewTLS(t, func(s *h2racetest.Stream) *h2racetest.Reply {
		return &h2racetest.Reply{Status: 200, Body: "ok"}
	})
	req := Request{
		Method: "POST", Scheme: "https", Authority: srv.Addr(), Path: "/",
		Header: []Header{
			{Name: "Content-Length", Value: "99"},
			{Name: "transfer-encoding", Value: "chunked"},
		},
		Body: []byte("0\r\n\r\nX"),
	}
	resps, err := SinglePacket(context.Background(), Target{Host: srv.Host, Port: srv.Port, TLS: true}, []Request{req}, Options{Timeout: 3 * time.Second})
	require.NoError(t, err)
	require.NoError(t, resps[0].Err)
	assert.Equal(t, 200, resps[0].Status)
	assert.Equal(t, "ok", string(resps[0].Body))

	got := srv.Streams()
	require.Len(t, got, 1)
	assert.Equal(t, "99", got[0].Value("content-length"), "a content-length disagreeing with DATA is sent verbatim")
	assert.Equal(t, "chunked", got[0].Value("transfer-encoding"))
	assert.Equal(t, "0\r\n\r\nX", string(got[0].Body))
	assert.Equal(t, "POST", got[0].Value(":method"))
}

func TestSinglePacket_ConformingServerResetsTransferEncoding(t *testing.T) {
	ts := newH2Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
	}))
	req := post(ts.Listener.Addr().String(), "/", "0\r\n\r\n")
	req.Header = append(req.Header, Header{Name: "transfer-encoding", Value: "chunked"})
	resps, err := SinglePacket(context.Background(), targetOf(t, ts.URL), []Request{req}, Options{Timeout: 3 * time.Second})
	require.NoError(t, err)
	// x/net's server answers a malformed (connection-specific) header with
	// 400; a stream reset is the other conforming reaction.
	rejected := resps[0].Status == 400 || errors.Is(resps[0].Err, ErrStreamReset)
	assert.True(t, rejected, "status %d err %v", resps[0].Status, resps[0].Err)
}

func TestSinglePacket_StalledStreamTimesOut(t *testing.T) {
	srv := h2racetest.NewTLS(t, func(s *h2racetest.Stream) *h2racetest.Reply {
		if s.Value(":path") == "/stall" {
			return nil
		}
		return &h2racetest.Reply{Status: 204}
	})
	tg := Target{Host: srv.Host, Port: srv.Port, TLS: true}
	reqs := []Request{post(srv.Addr(), "/ok", "a"), post(srv.Addr(), "/stall", "b")}
	start := time.Now()
	resps, err := SinglePacket(context.Background(), tg, reqs, Options{Timeout: 400 * time.Millisecond})
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 3*time.Second)
	require.NoError(t, resps[0].Err)
	assert.Equal(t, 204, resps[0].Status)
	assert.ErrorIs(t, resps[1].Err, ErrTimeout)
	assert.Contains(t, resps[1].Dump(), "no response")
}

func TestSinglePacket_NotH2(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ts.Close)
	_, err := SinglePacket(context.Background(), targetOf(t, ts.URL), []Request{post("x", "/", "a")}, Options{Timeout: 2 * time.Second})
	assert.ErrorIs(t, err, ErrNotH2)

	_, err = SinglePacket(context.Background(), Target{Host: "127.0.0.1", Port: 1}, []Request{post("x", "/", "a")}, Options{})
	assert.ErrorIs(t, err, ErrNotH2, "plain-text targets have no ALPN")
}

func TestSinglePacket_RefusesBatchOverStreamLimit(t *testing.T) {
	srv := h2racetest.NewTLS(t, func(s *h2racetest.Stream) *h2racetest.Reply { return &h2racetest.Reply{Status: 200} })
	reqs := make([]Request, 101) // the test server advertises 100
	for i := range reqs {
		reqs[i] = post(srv.Addr(), "/", "x")
	}
	_, err := SinglePacket(context.Background(), Target{Host: srv.Host, Port: srv.Port, TLS: true}, reqs, Options{Timeout: 2 * time.Second})
	assert.ErrorIs(t, err, ErrTooManyStreams)
}

func TestLastByteSync_ReleasesTogether(t *testing.T) {
	var a arrivals
	ts := httptest.NewServer(a.handler())
	t.Cleanup(ts.Close)

	const n = 5
	const settle = 250 * time.Millisecond
	reqs := make([]Request, n)
	for i := range reqs {
		reqs[i] = post(ts.Listener.Addr().String(), "/redeem", "code="+strconv.Itoa(i))
	}
	resps, err := LastByteSync(context.Background(), targetOf(t, ts.URL), reqs, Options{Timeout: 5 * time.Second, Settle: settle})
	require.NoError(t, err)
	for i, r := range resps {
		require.NoError(t, r.Err)
		assert.Equal(t, 200, r.Status)
		assert.Equal(t, "HTTP/1.1", r.Proto)
		assert.Equal(t, "echo:code="+strconv.Itoa(i), string(r.Body))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, lastStart := spread(a.started)
	firstEnd, lastEnd := spread(a.finished)
	assert.GreaterOrEqual(t, firstEnd.Sub(lastStart), settle-50*time.Millisecond)
	assert.Less(t, lastEnd.Sub(firstEnd), 50*time.Millisecond)
}

func TestLastByteSync_TLSFallback(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
	}))
	t.Cleanup(ts.Close)
	resps, err := LastByteSync(context.Background(), targetOf(t, ts.URL), []Request{post("x", "/", "")}, Options{Timeout: 3 * time.Second})
	require.NoError(t, err)
	require.NoError(t, resps[0].Err)
	assert.Equal(t, 201, resps[0].Status)
}

// connectProxy is a minimal HTTP CONNECT proxy that records tunnel targets.
type connectProxy struct {
	ln      net.Listener
	mu      sync.Mutex
	targets []string
	wg      sync.WaitGroup
}

func newConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &connectProxy{ln: ln}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.serve(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); p.wg.Wait() })
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
}

func TestSinglePacket_ThroughConnectProxy(t *testing.T) {
	var a arrivals
	ts := newH2Server(t, a.handler())
	proxy := newConnectProxy(t)
	tg := targetOf(t, ts.URL)

	reqs := []Request{post(ts.Listener.Addr().String(), "/", "a"), post(ts.Listener.Addr().String(), "/", "b")}
	resps, err := SinglePacket(context.Background(), tg, reqs, Options{Timeout: 3 * time.Second, ProxyURL: "http://" + proxy.ln.Addr().String()})
	require.NoError(t, err)
	for _, r := range resps {
		require.NoError(t, r.Err)
		assert.Equal(t, 200, r.Status)
	}
	proxy.mu.Lock()
	assert.Equal(t, []string{tg.addr()}, proxy.targets)
	proxy.mu.Unlock()

	// The H1 fallback tunnels too, one CONNECT per connection.
	h1 := httptest.NewServer(a.handler())
	t.Cleanup(h1.Close)
	resps, err = LastByteSync(context.Background(), targetOf(t, h1.URL), reqs, Options{Timeout: 3 * time.Second, ProxyURL: "http://" + proxy.ln.Addr().String()})
	require.NoError(t, err)
	for _, r := range resps {
		require.NoError(t, r.Err)
	}
	proxy.mu.Lock()
	assert.Len(t, proxy.targets, 3)
	proxy.mu.Unlock()
}

func TestDial_RefusesNonHTTPProxy(t *testing.T) {
	_, err := SinglePacket(context.Background(), Target{Host: "127.0.0.1", Port: 443, TLS: true},
		[]Request{post("x", "/", "a")}, Options{Timeout: time.Second, ProxyURL: "socks5://127.0.0.1:1080"})
	assert.True(t, errors.Is(err, ErrUnsupportedProxy), "got %v", err)
}

func TestRequest_WireH1(t *testing.T) {
	r := post("example.test", "/a?b=1", "x=1")
	wire := string(r.WireH1())
	assert.True(t, strings.HasPrefix(wire, "POST /a?b=1 HTTP/1.1\r\nHost: example.test\r\n"))
	assert.Contains(t, wire, "Content-Length: 3\r\n\r\nx=1")

	r.Header = append(r.Header, Header{Name: "Content-Length", Value: "0"})
	wire = string(r.WireH1())
	assert.Equal(t, 1, strings.Count(wire, "Content-Length"), "a caller-set length is kept verbatim")

	get := Request{Method: "GET", Authority: "h", Path: "/"}
	assert.NotContains(t, string(get.WireH1()), "Content-Length")
}

func TestEnvProxyURL_Order(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(k, "")
	}
	assert.Empty(t, EnvProxyURL())
	t.Setenv("https_proxy", "http://late:1")
	t.Setenv("HTTP_PROXY", "http://first:1")
	assert.Equal(t, "http://first:1", EnvProxyURL())
}
