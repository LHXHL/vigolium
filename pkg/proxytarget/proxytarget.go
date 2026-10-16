// Package proxytarget keeps a plain-HTTP request's destination intact when it
// is forwarded through an HTTP proxy (Burp, --proxy http://…, HTTP_PROXY).
//
// A forward proxy routes a plain-HTTP request by the absolute-form request
// target ("GET http://host:port/path HTTP/1.1"), and net/http writes that
// target from req.Host, not req.URL.Host (Request.write in net/http). When the
// Host header deliberately differs from the URL being fetched — a
// Host-header-injection probe, a fuzzed Host, a vhost probe, a replay
// retargeted at another environment, or a Host captured without the port —
// the proxy is told to fetch the Host header's authority and forwards the
// request there instead of to the target.
//
// Transport fixes that one case: for a plain-HTTP request sent through an HTTP
// or HTTPS proxy whose Host differs from req.URL.Host, it sends the absolute
// form built from req.URL (scheme://host:port/path) while the Host header still
// carries the override. Every other request passes through unchanged: direct
// connections, SOCKS proxies (which dial req.URL's host:port), and https
// targets (tunnelled with CONNECT to req.URL's host:port).
package proxytarget

import (
	"net/http"
	"strings"
)

// Transport is an *http.Transport whose RoundTrip keeps req.URL's authority in
// the request target sent to an HTTP proxy. The embedded transport carries all
// configuration (Proxy, TLS, dialers, pools); its other methods, such as
// CloseIdleConnections, are promoted unchanged. Safe for concurrent use.
type Transport struct {
	*http.Transport
}

// Wrap returns t behind the proxy-target fix. A nil t wraps a zero-value
// *http.Transport.
func Wrap(t *http.Transport) *Transport {
	if t == nil {
		t = &http.Transport{}
	}
	return &Transport{Transport: t}
}

// Base returns the *http.Transport behind rt: rt itself when it is one, the
// embedded transport when rt is a *Transport, else nil and false. Callers that
// adjust a client's transport after construction use it so wrapping does not
// hide the transport from them.
func Base(rt http.RoundTripper) (*http.Transport, bool) {
	switch t := rt.(type) {
	case *http.Transport:
		return t, t != nil
	case *Transport:
		if t != nil && t.Transport != nil {
			return t.Transport, true
		}
	}
	return nil, false
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.needsAbsoluteTarget(req) {
		req = withAbsoluteTarget(req)
	}
	return t.Transport.RoundTrip(req)
}

// needsAbsoluteTarget reports whether net/http would name the wrong authority
// in the request target for req: a plain-HTTP request, going through an HTTP or
// HTTPS proxy, whose Host differs from the URL it fetches.
func (t *Transport) needsAbsoluteTarget(req *http.Request) bool {
	u := req.URL
	if u == nil || u.Opaque != "" || u.Host == "" || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	if req.Host == "" || req.Host == u.Host || req.Method == http.MethodConnect {
		return false
	}
	// An IPv6 zone must not appear in an outgoing URI (RFC 6874); net/http
	// strips it from the target it writes, so leave such a request to it.
	if strings.Contains(u.Host, "%") {
		return false
	}
	if p := u.EscapedPath(); p != "" && !strings.HasPrefix(p, "/") {
		return false
	}
	if t.Proxy == nil {
		return false
	}
	proxyURL, err := t.Proxy(req)
	if err != nil || proxyURL == nil {
		return false
	}
	// net/http speaks SOCKS to socks5/socks5h proxies and dials req.URL's
	// host:port through them; every other proxy scheme gets the absolute form.
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		return false
	}
	return true
}

// withAbsoluteTarget returns a copy of req whose request target is the absolute
// form of req.URL. net/http writes URL.Opaque verbatim as the request target
// (prefixed with "scheme:" when it starts with "//"), so the target carries
// URL.Host while the Host header keeps req.Host. EscapedPath preserves the
// caller's percent-encoding, which is the payload for path-normalization probes.
func withAbsoluteTarget(req *http.Request) *http.Request {
	out := req.Clone(req.Context())
	path := out.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	out.URL.Opaque = "//" + out.URL.Host + path
	return out
}
