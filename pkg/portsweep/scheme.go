package portsweep

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// SchemeConnectTimeout bounds the "is this port open" question for a target
// whose scheme is not known.
//
// It is deliberately far shorter than an HTTP timeout, because the two answer
// different questions. A filtered port runs the full read timeout before a
// request can conclude anything — 21s per dead host on the default --timeout.
// Whether a TCP connect completes is answered in one round trip or not at all,
// so the bound can be tight without shortening the read for a host that is
// simply slow to render.
const SchemeConnectTimeout = 3 * time.Second

// SchemeTLSTimeout bounds the "does this port speak TLS" handshake, asked only
// for an explicit non-standard port (see ResolveScheme). Slightly longer than a
// bare connect because it is a connect plus a handshake.
const SchemeTLSTimeout = 5 * time.Second

// SchemeOptions tunes ResolveScheme for its caller.
type SchemeOptions struct {
	// PreferTLS flips the order ports are tried in when the target names no
	// port: 443 before 80. The host sweep keeps http first (a host answering
	// today keeps a byte-identical record, and the http -> https hop is itself
	// a signal); a captured raw request whose Host header carries no port was
	// almost always sent over TLS, so scan-request asks for https first.
	PreferTLS bool
}

// SchemeResolution is the transport ResolveScheme settled on for one target.
type SchemeResolution struct {
	// URL is the target rewritten with a concrete scheme (and the explicit port,
	// when it had one). Empty when Reachable is false.
	URL string
	// Reachable is false when no candidate port accepted a TCP connect, so the
	// caller can skip the request entirely instead of paying the read timeout.
	Reachable bool
	// Scheme is "http" or "https" when Reachable.
	Scheme string
	// Probed reports that network traffic decided the scheme (a connect, or a
	// connect plus a TLS handshake). False when the port alone decided it
	// (an explicit :80 or :443), which costs nothing.
	Probed bool
}

// ResolveScheme decides which scheme a target whose scheme is unknown should be
// contacted over, and whether it is worth contacting at all. It is the one
// implementation behind the host sweep's schemeless targets and scan-request's
// raw requests that carry no scheme signal.
//
// Every question is answered with a TCP connect (and, in one case, a TLS
// handshake), which is cheaper than a request and carries its own short
// timeout. What it replaces is a guess — schemeless meant http (the sweep) or
// https (scan-request), full stop — that reported every host speaking the other
// transport as dead.
//
// host is the bare hostname or IP, port the explicit port ("" when the target
// named none) and rest the escaped path and query carried onto the rewritten URL.
//
// The rules, and why each is the way round it is:
//
//   - No explicit port: try 80, then 443 (443 first under PreferTLS). A
//     connect on 443 is taken as TLS and one on 80 as plaintext.
//   - Explicit :443: https, no probe. The port is the operator saying TLS.
//   - Explicit :80: http, no probe. Same, in the other direction. A closed
//     :80 still reaches the request and fails there.
//   - Any other explicit port: a connect cannot tell plaintext from TLS, so
//     ask with a handshake. This is the case a connect alone gets wrong — a
//     TLS service on :8443 accepts the connection and then rejects a plaintext
//     request, and an http dev server on :3000 accepts it and then fails the
//     handshake.
//
// The default port is left OFF the rewritten URL: writing it back would turn
// `example.com` into `http://example.com:80/`, the same endpoint under a
// different record URL.
func ResolveScheme(ctx context.Context, host, port, rest string, opts SchemeOptions) SchemeResolution {
	build := func(scheme, authority string, probed bool) SchemeResolution {
		return SchemeResolution{URL: scheme + "://" + authority + rest, Reachable: true, Scheme: scheme, Probed: probed}
	}
	authority := host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		authority = "[" + host + "]" // IPv6 literal
	}

	if port == "" {
		order := []struct {
			port   int
			scheme string
		}{{80, "http"}, {443, "https"}}
		if opts.PreferTLS {
			order[0], order[1] = order[1], order[0]
		}
		for _, c := range order {
			if schemeDialOpen(ctx, host, c.port) {
				return build(c.scheme, authority, true)
			}
		}
		return SchemeResolution{}
	}

	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return SchemeResolution{}
	}
	switch p {
	case 443:
		return build("https", authority, false)
	case 80:
		return build("http", authority, false)
	}

	explicit := net.JoinHostPort(host, port)
	if !schemeDialOpen(ctx, host, p) {
		return SchemeResolution{}
	}
	if info := tlsprobe.Probe(ctx, host, p, SchemeTLSTimeout); info != nil && info.ProbeStatus {
		return build("https", explicit, true)
	}
	return build("http", explicit, true)
}

// schemeDialOpen reports whether a TCP connect to host:port completes within
// SchemeConnectTimeout. A refused, reset, filtered or unresolvable endpoint all
// answer false — the caller only needs "is there something to talk to".
// TCPReachable does the connect so the port sweep and the scheme resolver
// cannot end up with two answers to the same question.
func schemeDialOpen(ctx context.Context, host string, port int) bool {
	// One timeout, on the context, so cancellation propagates and the dialer
	// does not arm a second timer for the same bound.
	dialCtx, cancel := context.WithTimeout(ctx, SchemeConnectTimeout)
	defer cancel()
	return TCPReachable(dialCtx, schemeDialer, host, port)
}

// schemeDialer is the connect-probe dialer, shared by every resolution.
// Deliberately a plain net.Dialer rather than the scan-wide fastdialer: the
// question is per-endpoint and asked before any requester is used, and
// fastdialer's value here (DNS caching, deny lists) is either applied upstream
// (scope admission ran first) or not needed for a single connect.
var schemeDialer = &net.Dialer{Timeout: SchemeConnectTimeout}
