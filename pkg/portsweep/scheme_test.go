package portsweep

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// The scheme resolver is the one implementation behind the host sweep's
// schemeless targets (internal/runner/probe_scheme.go) and scan-request's
// scheme probe (pkg/cli/scan_request_scheme.go); these cases moved here from
// the runner when it became shared.

// closedSchemePort returns a host and port that nothing is listening on, by
// binding and immediately releasing it. Racy in principle, reliable in practice
// and far cheaper than reserving a range.
func closedSchemePort(t *testing.T) (string, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return host, port
}

func schemeHostPort(t *testing.T, raw string) (string, string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname(), u.Port()
}

// A target on an open plaintext port must resolve to http, so every host that
// answers today produces a byte-identical record.
func TestResolveSchemePlaintextPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer srv.Close()

	host, port := schemeHostPort(t, srv.URL)
	got := ResolveScheme(context.Background(), host, port, "", SchemeOptions{})
	if !got.Reachable || !got.Probed {
		t.Fatalf("an open plaintext port must be reachable and probed: %+v", got)
	}
	if want := "http://" + net.JoinHostPort(host, port); got.URL != want || got.Scheme != "http" {
		t.Errorf("url = %q scheme = %q, want %q", got.URL, got.Scheme, want)
	}
}

// The headline case: a TLS-only service on a non-standard port. A connect
// answers "open", and only the handshake answers "TLS".
func TestResolveSchemeTLSPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tls"))
	}))
	defer srv.Close()

	host, port := schemeHostPort(t, srv.URL)
	got := ResolveScheme(context.Background(), host, port, "", SchemeOptions{})
	if !got.Reachable {
		t.Fatal("an open TLS port must be reachable")
	}
	if want := "https://" + net.JoinHostPort(host, port); got.URL != want || got.Scheme != "https" {
		t.Errorf("url = %q, want %q — a TLS-only host is still being probed over http", got.URL, want)
	}
}

// Nothing is requested when nothing is listening, and the answer is bounded by
// the connect timeout rather than an HTTP read timeout.
func TestResolveSchemeClosedPort(t *testing.T) {
	host, port := closedSchemePort(t)
	start := time.Now()
	got := ResolveScheme(context.Background(), host, port, "", SchemeOptions{})
	if got.Reachable || got.URL != "" {
		t.Errorf("a closed port must not be reported reachable: %+v", got)
	}
	if elapsed := time.Since(start); elapsed > SchemeConnectTimeout+time.Second {
		t.Errorf("took %s; the decision must be bounded by the connect timeout (%s)", elapsed, SchemeConnectTimeout)
	}
}

// 80 and 443 are answered from the port alone, with no probe, and neither
// writes its default port back into the URL.
func TestResolveSchemeWellKnownPorts(t *testing.T) {
	for _, tc := range []struct{ port, want string }{
		{"443", "https://example.test/x"},
		{"80", "http://example.test/x"},
	} {
		got := ResolveScheme(context.Background(), "example.test", tc.port, "/x", SchemeOptions{})
		if !got.Reachable || got.URL != tc.want || got.Probed {
			t.Errorf("port %s: %+v, want %q reachable, not probed", tc.port, got, tc.want)
		}
	}
}

// selfSignedSchemeListener proves the resolver does not depend on a trusted
// certificate: scan targets routinely present self-signed ones, and refusing
// them would reintroduce the false negative under a different name.
func selfSignedSchemeListener(t *testing.T) net.Listener {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return l
}

func TestResolveSchemeAcceptsSelfSignedCert(t *testing.T) {
	l := selfSignedSchemeListener(t)
	defer func() { _ = l.Close() }()

	host, port, _ := net.SplitHostPort(l.Addr().String())
	got := ResolveScheme(context.Background(), host, port, "", SchemeOptions{})
	if !got.Reachable || got.URL != "https://"+net.JoinHostPort(host, port) {
		t.Errorf("%+v; a self-signed cert must not make a host look dead", got)
	}
}
