package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// newHTTP2FallbackTransport builds the transport for retryablehttp's HTTP/2
// fallback client: the second client it retries a request on when an HTTP/1.x
// read fails with "malformed HTTP version \"HTTP/2\"".
//
// retryablehttp builds that client itself, from its own defaults —
// ProxyFromEnvironment and a private fastdialer — so a fallback request ignored
// --proxy, bypassed the proxy for a loopback target, and skipped the scan's
// dialer. This transport carries the scan's stance instead: the scan dialer, the
// target TLS policy and the same explicit proxy as the primary transport.
//
// It differs from the primary transport only where HTTP/2 needs it to: there is
// no custom DialTLSContext (Go must run the TLS handshake itself so ALPN can
// negotiate h2, which is the point of this client), and keep-alives are off, as
// in retryablehttp's own fallback — this client serves the odd request, not a
// pool. If HTTP/2 cannot be configured the transport is returned as plain
// HTTP/1.1, still proxy-aware: a fallback that fails is better than one that
// leaves through the wrong exit.
func newHTTP2FallbackTransport(
	dial func(context.Context, string, string) (net.Conn, error),
	tlsConfig *tls.Config,
	cliProxy string,
	responseHeaderTimeout time.Duration,
) *http.Transport {
	var tlsCfg *tls.Config
	if tlsConfig != nil {
		tlsCfg = tlsConfig.Clone()
	}
	t := &http.Transport{
		DialContext:            dial,
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		MaxResponseHeaderBytes: 48 * 1024,
	}
	applyExplicitProxy(t, cliProxy, "scanner-h2-fallback")
	if err := http2.ConfigureTransport(t); err != nil {
		zap.L().Debug("HTTP/2 fallback transport left at HTTP/1.1", zap.Error(err))
	}
	return t
}

// pinHTTP2Fallback points c's HTTP/2 fallback client at h2, inheriting the
// primary client's timeout, cookie jar and redirect policy so a request that
// falls back behaves like the one it replaces (retryablehttp's own fallback
// followed every redirect, even on the no-redirect client). A nil h2 leaves c
// untouched.
func pinHTTP2Fallback(c *retryablehttp.Client, h2 http.RoundTripper) {
	if c == nil || c.HTTPClient == nil || h2 == nil {
		return
	}
	fallback := *c.HTTPClient
	fallback.Transport = h2
	c.HTTPClient2 = &fallback
}
