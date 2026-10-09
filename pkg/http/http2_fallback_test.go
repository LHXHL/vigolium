package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestHTTP2Fallback_FollowsTheProxyFlag: retryablehttp retries a request on its
// own HTTP/2 client when an HTTP/1.x read sees an HTTP/2 response. That client
// used to come from retryablehttp's defaults (ProxyFromEnvironment, which also
// bypasses loopback), so a fallback request left around --proxy. Every retry
// client a Requester owns — including the cookie-isolated clones — must send
// its fallback through the scan's proxy.
func TestHTTP2Fallback_FollowsTheProxyFlag(t *testing.T) {
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "127.0.0.1:1" {
			proxied.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	opts := types.DefaultOptions()
	opts.ProxyURL = proxy.URL
	r := newTestRequesterWithOpts(t, opts)
	clone, err := r.CloneWithoutCredentials()
	if err != nil {
		t.Fatalf("CloneWithoutCredentials: %v", err)
	}

	clients := map[string]*retryablehttp.Client{
		"client":              r.client,
		"clientNoRedir":       r.clientNoRedir,
		"clone.client":        clone.client,
		"clone.clientNoRedir": clone.clientNoRedir,
	}
	for name, c := range clients {
		before := proxied.Load()
		// Port 1 on loopback is closed: only the proxy can answer this.
		resp, err := c.HTTPClient2.Get("http://127.0.0.1:1/fallback")
		if err != nil {
			t.Errorf("%s: HTTP/2 fallback request did not go through the proxy: %v", name, err)
			continue
		}
		_ = resp.Body.Close()
		if proxied.Load() != before+1 {
			t.Errorf("%s: proxy did not see the fallback request", name)
		}
	}

	// The fallback inherits its primary client's redirect policy.
	if cr := r.clientNoRedir.HTTPClient2.CheckRedirect; cr == nil ||
		!errors.Is(cr(nil, nil), http.ErrUseLastResponse) {
		t.Error("clientNoRedir's HTTP/2 fallback follows redirects; it must stop at the first response")
	}
}
