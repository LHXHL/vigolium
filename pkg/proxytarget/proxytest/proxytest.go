// Package proxytest provides a recording forward HTTP proxy for tests that
// assert what a client puts on the wire to a proxy.
//
// A net/http server cannot serve as that proxy: on an absolute-form request it
// replaces Request.Host with the target's authority and deletes the Host header
// (RFC 9112 §3.2.2), so the Host the client sent is unobservable. This proxy
// reads the request head itself, records the request target and the Host
// header verbatim, and forwards the request to the absolute URL with its Host
// header unchanged — the way Burp's proxy listener forwards traffic.
package proxytest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Hit is one request the proxy received.
type Hit struct {
	// RequestTarget is the request-line target as sent, e.g.
	// "http://127.0.0.1:8080/x?q=1".
	RequestTarget string
	// Host is the Host header as sent ("" when absent).
	Host string
}

// Proxy is a running recording proxy. Close is registered with t.Cleanup.
type Proxy struct {
	// URL is the proxy's address, e.g. http://127.0.0.1:54321.
	URL *url.URL

	ln   net.Listener
	mu   sync.Mutex
	hits []Hit
	wg   sync.WaitGroup
}

// New starts a recording proxy on a random loopback port.
func New(t testing.TB) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxytest: listen: %v", err)
	}
	p := &Proxy{URL: &url.URL{Scheme: "http", Host: ln.Addr().String()}, ln: ln}
	p.wg.Add(1)
	go p.serve()
	t.Cleanup(p.Close)
	return p
}

// Hits returns the requests received so far, in arrival order.
func (p *Proxy) Hits() []Hit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Hit(nil), p.hits...)
}

// Close stops the proxy and waits for in-flight connections.
func (p *Proxy) Close() {
	_ = p.ln.Close()
	p.wg.Wait()
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			p.handle(conn)
		}()
	}
}

// handle serves one request per connection: record, forward, relay, close.
// A body is forwarded when the request declares a Content-Length.
func (p *Proxy) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) != 3 {
		return
	}
	method, target, proto := parts[0], parts[1], parts[2]

	var (
		host          string
		headers       []string
		contentLength int64
	)
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		if name, value, ok := strings.Cut(h, ":"); ok {
			switch {
			case strings.EqualFold(name, "Host"):
				host = strings.TrimSpace(value)
			case strings.EqualFold(name, "Content-Length"):
				contentLength, _ = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			case strings.EqualFold(name, "Proxy-Connection"), strings.EqualFold(name, "Connection"):
				continue
			}
		}
		headers = append(headers, h)
	}

	p.mu.Lock()
	p.hits = append(p.hits, Hit{RequestTarget: target, Host: host})
	p.mu.Unlock()

	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		writeStatus(conn, http.StatusBadRequest)
		return
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "80")
	}
	up, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer func() { _ = up.Close() }()
	_ = up.SetDeadline(time.Now().Add(10 * time.Second))

	var b strings.Builder
	b.WriteString(method + " " + u.RequestURI() + " " + proto + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := up.Write([]byte(b.String())); err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	if contentLength > 0 {
		if _, err := io.CopyN(up, br, contentLength); err != nil {
			writeStatus(conn, http.StatusBadGateway)
			return
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), nil)
	if err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	resp.Close = true
	_ = resp.Write(conn)
}

func writeStatus(conn net.Conn, code int) {
	resp := &http.Response{StatusCode: code, ProtoMajor: 1, ProtoMinor: 1, Close: true}
	_ = resp.Write(conn)
}
