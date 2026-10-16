package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
	"github.com/vigolium/vigolium/pkg/replay"
)

// TestReplayAndFuzzClientsKeepPortThroughProxy: `vigolium replay` and
// `vigolium fuzz` build their clients from --proxy (globalProxy). Through an
// HTTP proxy, a target on a non-default port must be requested as host:port,
// for the request's own Host and for a fuzzed or retargeted Host alike.
func TestReplayAndFuzzClientsKeepPortThroughProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("target-ok"))
	}))
	defer target.Close()
	addr := target.Listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	proxy := proxytest.New(t)
	prev := globalProxy
	globalProxy = proxy.URL.String()
	t.Cleanup(func() { globalProxy = prev })

	fuzzClient, err := buildFuzzClient(nil)
	if err != nil {
		t.Fatalf("buildFuzzClient: %v", err)
	}
	clients := map[string]*http.Client{
		"replay": newReplayClient(nil, 0),
		"fuzz":   fuzzClient,
	}
	for name, client := range clients {
		for _, hostHeader := range []string{addr, "vhost.example"} {
			before := len(proxy.Hits())
			raw := "GET /p HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n"
			sum := replay.SendRaw(context.Background(), client, []byte(raw), "http", host, port, true, 0)
			if sum.Error != "" || sum.Status != http.StatusOK || string(sum.RawBody) != "target-ok" {
				t.Fatalf("%s, Host %q: did not reach the target through the proxy: status=%d err=%q",
					name, hostHeader, sum.Status, sum.Error)
			}
			hits := proxy.Hits()[before:]
			if len(hits) != 1 || hits[0].RequestTarget != "http://"+addr+"/p" || hits[0].Host != hostHeader {
				t.Errorf("%s: proxy saw %+v, want target http://%s/p with Host %q", name, hits, addr, hostHeader)
			}
		}
	}
}
