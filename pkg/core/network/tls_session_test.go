package network

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/vigolium/vigolium/pkg/core/network/networktest"
)

// The resumable fastdialer config carries the shared cache without touching
// fastdialer's package default, which other code shares.
func TestResumableFastdialerTLS(t *testing.T) {
	if resumableFastdialerTLS.ClientSessionCache != TLSSessionCache() {
		t.Error("resumable fastdialer config lacks the shared session cache")
	}
	if fastdialer.DefaultTLSConfig.ClientSessionCache != nil {
		t.Error("fastdialer.DefaultTLSConfig was mutated")
	}
}

func TestSharedCacheResumesAcrossConnections(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: TLSSessionCache()} //nolint:gosec // test
	networktest.AssertResumes(t, &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}})
}
