package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

// PoolConfig.Protocol picks the client's wire protocol: "" keeps discovery's
// historical HTTP/1.1, a multiplexing policy negotiates HTTP/2 with an origin
// that offers it.
func TestClientProtocolPolicy(t *testing.T) {
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusNoContent)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	for _, tc := range []struct {
		protocol  string
		wantMajor int
	}{
		{"", 1},
		{"http1", 1},
		{"http2", 2},
		{"auto", 2}, // no HTTP/3 listener: falls to TCP
	} {
		t.Run("protocol="+tc.protocol, func(t *testing.T) {
			pool := DefaultPoolConfig()
			pool.Protocol = tc.protocol
			c := NewClient(&ClientConfig{PoolConfig: pool})
			defer c.CloseIdleConnections()
			req, _ := NewRequest(srv.URL + "/x").Build()
			rc, err := c.Send(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			major := rc.Response().ProtoMajor
			rc.Close()
			if major != tc.wantMajor {
				t.Errorf("response over HTTP/%d, want HTTP/%d", major, tc.wantMajor)
			}
		})
	}
}
