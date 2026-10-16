package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server/mitm"
)

// TestIngestProxy_MITMHostlessRequestKeepsPort: an HTTP/1.0 client inside an
// intercepted CONNECT tunnel may send no Host header. The proxy re-originates
// the request with the CONNECT authority as its Host, and that authority's
// non-default port must survive — a bare hostname names a different origin
// (RFC 9110 §7.2), so a vhost-routed upstream answered for the wrong site.
func TestIngestProxy_MITMHostlessRequestKeepsPort(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up TLS listeners")
	}
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	if err := repo.CreateProject(ctx, &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	var (
		mu       sync.Mutex
		seenHost string
	)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenHost = r.Host
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	authority := upstream.Listener.Addr().String()

	ca, err := mitm.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	proxyURL := startProxy(t, newIngestProxy("127.0.0.1:0", db, repo, nil, nil, nil, ca, true, nil))

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyURL, "http://"), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: resp=%v err=%v", connectResp, err)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caCertPool(t, ca),
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the tunnel: %v", err)
	}
	if _, err := tlsConn.Write([]byte("GET /nohost HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	got := seenHost
	mu.Unlock()
	if got != authority {
		t.Errorf("upstream Host = %q, want the CONNECT authority %q", got, authority)
	}
}
