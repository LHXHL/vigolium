package http

import (
	nethttp "net/http"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network/networktest"
)

// TestPoolTransportResumesTLSSessions: discovery connections that the pool
// refills must resume their TLS session instead of redoing the handshake.
func TestPoolTransportResumesTLSSessions(t *testing.T) {
	networktest.AssertResumes(t, &nethttp.Client{Transport: DefaultPoolConfig().NewTransport()})
}
