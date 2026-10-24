package burpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestBridgeSenderPoolsConcurrentSends: fuzz --send-via-burp -c 10 sends ten
// bridge calls at once. On http.DefaultTransport only 2 idle connections were
// kept, so every round re-dialed most of them; the bridge pool must hold them.
func TestBridgeSenderPoolsConcurrentSends(t *testing.T) {
	const workers, rounds = 10, 5
	rawResp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	reply, _ := json.Marshal(map[string]any{
		"sent":            1,
		"status_code":     200,
		"response_base64": base64.StdEncoding.EncodeToString([]byte(rawResp)),
	})

	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(reply)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	client, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	send := BridgeSender(client, "https", "acme.test", 443, SendOptions{}, 0)
	raw := []byte("GET /x HTTP/1.1\r\nHost: acme.test\r\n\r\n")
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if sum := send(context.Background(), raw); sum.Status != 200 {
					t.Errorf("send: %+v", sum)
				}
			}()
		}
		wg.Wait()
	}
	if got := conns.Load(); got > workers {
		t.Errorf("bridge saw %d connections for %d rounds of %d concurrent sends, want at most %d", got, rounds, workers, workers)
	}
}
