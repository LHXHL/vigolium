package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
)

// TestClientHostHeaderThroughHTTPProxy: discovery requests carry the operator's
// custom headers, Host included (RequestBuilder moves it to req.Host). Through
// an HTTP proxy the request must still be fetched from the URL's host:port, and
// the custom Host must still reach the target. Without the proxytarget wrapper
// net/http names the Host header in the proxy request line, so the proxy went
// to the custom host instead.
func TestClientHostHeaderThroughHTTPProxy(t *testing.T) {
	var (
		mu       sync.Mutex
		lastHost string
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastHost = r.Host
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	addr := target.Listener.Addr().String()
	proxy := proxytest.New(t)

	cfg := DefaultClientConfig()
	cfg.PoolConfig.ProxyURL = proxy.URL.String()
	client := NewClient(cfg)
	defer client.CloseIdleConnections()

	for _, tc := range []struct{ name, host string }{
		{"custom host", "vhost.example"},
		{"no custom host", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantHost := tc.host
			rb := NewRequest("http://" + addr + "/admin/")
			if tc.host != "" {
				rb = rb.Header("Host", tc.host)
			} else {
				wantHost = addr
			}
			req, err := rb.Build()
			if err != nil {
				t.Fatal(err)
			}
			before := len(proxy.Hits())
			rc, err := client.Send(context.Background(), req)
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			status := rc.Response().StatusCode
			rc.Close()
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 from the target through the proxy", status)
			}
			hits := proxy.Hits()[before:]
			if len(hits) != 1 || hits[0].RequestTarget != "http://"+addr+"/admin/" || hits[0].Host != wantHost {
				t.Errorf("proxy saw %+v, want target http://%s/admin/ with Host %q", hits, addr, wantHost)
			}
			mu.Lock()
			got := lastHost
			mu.Unlock()
			if got != wantHost {
				t.Errorf("target Host = %q, want %q", got, wantHost)
			}
		})
	}
}
