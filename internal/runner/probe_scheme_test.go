package runner

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

// listenClosedPort returns a host and port that nothing is listening on, by
// binding and immediately releasing it. Racy in principle, reliable in practice
// and far cheaper than reserving a range.
func listenClosedPort(t *testing.T) (string, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()
	return host, port
}

func hostPortOf(t *testing.T, raw string) (string, string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname(), u.Port()
}

// TestResolveSweepSchemePlaintextPort covers the regression-guard half: a
// schemeless target on an open plaintext port must still resolve to http, so
// every host that answers today produces a byte-identical record.
func TestResolveSweepSchemePlaintextPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer srv.Close()

	host, port := hostPortOf(t, srv.URL)
	got := resolveSweepScheme(context.Background(), host, port, "")
	if !got.reachable {
		t.Fatal("an open plaintext port must be reachable")
	}
	if want := "http://" + net.JoinHostPort(host, port); got.url != want {
		t.Errorf("url = %q, want %q", got.url, want)
	}
}

// TestResolveSweepSchemeTLSPort is the headline case: a TLS-only service on a
// non-standard port, given schemeless, used to be reported dead because the
// port alone cannot say which transport it speaks. A connect answers "open",
// and only the handshake answers "TLS".
func TestResolveSweepSchemeTLSPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tls"))
	}))
	defer srv.Close()

	host, port := hostPortOf(t, srv.URL)
	got := resolveSweepScheme(context.Background(), host, port, "")
	if !got.reachable {
		t.Fatal("an open TLS port must be reachable")
	}
	if want := "https://" + net.JoinHostPort(host, port); got.url != want {
		t.Errorf("url = %q, want %q — a TLS-only host is still being probed over http", got.url, want)
	}
}

// TestResolveSweepSchemeClosedPort pins that nothing is requested when nothing
// is listening. The saving is the point: an unreachable target used to burn the
// full HTTP read timeout before the sweep could conclude anything.
func TestResolveSweepSchemeClosedPort(t *testing.T) {
	host, port := listenClosedPort(t)
	start := time.Now()
	got := resolveSweepScheme(context.Background(), host, port, "")
	if got.reachable {
		t.Error("a closed port must not be reported reachable")
	}
	if elapsed := time.Since(start); elapsed > sweepConnectTimeout+time.Second {
		t.Errorf("took %s; the decision must be bounded by the connect timeout (%s)", elapsed, sweepConnectTimeout)
	}
}

// TestResolveSweepSchemeWellKnownPorts pins that 80 and 443 are answered from
// the port alone, with no probe, and that neither writes its default port back
// into the URL (which would change the record URL of every target that already
// worked).
func TestResolveSweepSchemeWellKnownPorts(t *testing.T) {
	for _, tc := range []struct{ port, want string }{
		{"443", "https://example.test/x"},
		{"80", "http://example.test/x"},
	} {
		got := resolveSweepScheme(context.Background(), "example.test", tc.port, "/x")
		if !got.reachable || got.url != tc.want {
			t.Errorf("port %s: url=%q reachable=%v, want %q true", tc.port, got.url, got.reachable, tc.want)
		}
	}
}

// TestSplitSweepTargetCarriesPath pins that the path and query survive the
// rewrite. Dropping them would silently re-point every target that named one.
func TestSplitSweepTargetCarriesPath(t *testing.T) {
	host, port, rest, ok := splitSweepTarget("http://example.test:8443/a/b?q=1")
	if !ok || host != "example.test" || port != "8443" || rest != "/a/b?q=1" {
		t.Fatalf("got host=%q port=%q rest=%q ok=%v", host, port, rest, ok)
	}
	// IPv6 literals split on the brackets, not on the last colon.
	host, port, _, ok = splitSweepTarget("http://[::1]:8443/")
	if !ok || host != "::1" || port != "8443" {
		t.Errorf("IPv6: host=%q port=%q ok=%v", host, port, ok)
	}
}

// TestApplyResolvedSchemes pins the three outcomes the target list can have:
// rewritten, dropped, or passed through untouched.
func TestApplyResolvedSchemes(t *testing.T) {
	targets := []string{"http://guessed.test", "http://explicit.test", "http://dead.test"}
	resolved := map[string]sweepScheme{
		"http://guessed.test": {url: "https://guessed.test", reachable: true},
		"http://dead.test":    {},
	}
	out, dropped := applyResolvedSchemes(targets, resolved)
	want := []string{"https://guessed.test", "http://explicit.test"}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("out[%d] = %q, want %q", i, out[i], want[i])
		}
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 — the summary's \"did not respond\" count depends on this", dropped)
	}
}

// selfSignedTLSListener exists to prove the resolver does not depend on a
// trusted certificate: scan targets routinely present self-signed ones, and
// refusing them would reintroduce the false negative under a different name.
func selfSignedTLSListener(t *testing.T) net.Listener {
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

func TestResolveSweepSchemeAcceptsSelfSignedCert(t *testing.T) {
	l := selfSignedTLSListener(t)
	defer func() { _ = l.Close() }()

	host, port, _ := net.SplitHostPort(l.Addr().String())
	got := resolveSweepScheme(context.Background(), host, port, "")
	if !got.reachable || got.url != "https://"+net.JoinHostPort(host, port) {
		t.Errorf("url=%q reachable=%v; a self-signed cert must not make a host look dead", got.url, got.reachable)
	}
}
