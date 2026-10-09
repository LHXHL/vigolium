package h2race

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dial opens a connection to t, through opts.ProxyURL when set, and runs the
// TLS handshake offering alpn when t.TLS. It returns the negotiated protocol
// ("" for plain TCP or when the server picked none).
func dial(ctx context.Context, t Target, opts Options, alpn []string) (net.Conn, string, error) {
	deadline := time.Now().Add(opts.timeout())
	nd := &net.Dialer{Deadline: deadline}

	var raw net.Conn
	var err error
	if opts.ProxyURL != "" {
		raw, err = dialViaConnect(ctx, nd, opts.ProxyURL, t.addr(), deadline)
	} else {
		raw, err = nd.DialContext(ctx, "tcp", t.addr())
	}
	if err != nil {
		return nil, "", err
	}
	if !t.TLS {
		return raw, "", nil
	}

	sni := t.ServerName
	if sni == "" && net.ParseIP(t.Host) == nil {
		sni = t.Host
	}
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner: targets routinely use self-signed certs
		MinVersion:         tls.VersionTLS10,
		ServerName:         sni,
		NextProtos:         alpn,
	})
	_ = tc.SetDeadline(deadline)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	return tc, tc.ConnectionState().NegotiatedProtocol, nil
}

// dialViaConnect opens a tunnel to addr through an HTTP CONNECT proxy.
func dialViaConnect(ctx context.Context, nd *net.Dialer, proxyURL, addr string, deadline time.Time) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("h2race: invalid proxy URL %q", proxyURL)
	}
	if !strings.EqualFold(pu.Scheme, "http") {
		return nil, fmt.Errorf("%w (got %q)", ErrUnsupportedProxy, pu.Scheme)
	}
	proxyAddr := pu.Host
	if pu.Port() == "" {
		proxyAddr = net.JoinHostPort(pu.Hostname(), "80")
	}
	conn, err := nd.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(deadline)

	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if pu.User != nil {
		pass, _ := pu.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(pu.User.Username() + ":" + pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("h2race: proxy CONNECT: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("h2race: proxy CONNECT to %s returned %d", addr, resp.StatusCode)
	}
	if br.Buffered() > 0 {
		// The tunnel must start clean: nothing may arrive before our first
		// byte. A proxy that pipelined data is not one we can frame over.
		_ = conn.Close()
		return nil, fmt.Errorf("h2race: proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}
	return conn, nil
}

// watchContext closes conn when ctx ends before done is closed.
func watchContext(ctx context.Context, done <-chan struct{}, conns ...net.Conn) {
	if ctx.Done() == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			for _, c := range conns {
				_ = c.Close()
			}
		case <-done:
		}
	}()
}
