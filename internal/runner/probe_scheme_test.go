package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The resolver's own cases (closed port, 80/443, self-signed TLS) live with the
// shared implementation in pkg/portsweep/scheme_test.go. The two below pin that
// the sweep reaches it with the sweep's policy (http first, handshake on an
// explicit non-standard port).

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
