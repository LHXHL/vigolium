package http

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network/networktest"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func httpsRecord(t *testing.T, addr string) *httpmsg.HttpRequestResponse {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	svc, err := httpmsg.NewService(h, port, "https")
	if err != nil {
		t.Fatal(err)
	}
	raw := "GET / HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(svc, []byte(raw)), nil)
}

// TestScanTransportResumesTLSSessions: every new scan connection used to pay a
// full handshake because no transport carried a ClientSessionCache. With the
// server closing each connection, the second and later requests must resume.
func TestScanTransportResumesTLSSessions(t *testing.T) {
	srvURL, resumed := networktest.ResumeServer(t)
	addr := strings.TrimPrefix(srvURL, "https://")
	r := newTestRequesterWithOpts(t, types.DefaultOptions())

	for i := 0; i < 3; i++ {
		if code := executeRecord(t, r, httpsRecord(t, addr)); code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, code)
		}
	}
	networktest.CheckResumed(t, resumed())
}
