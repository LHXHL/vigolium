package runner

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// sweepConnectTimeout bounds the "is this port open" question for a schemeless
// target.
//
// It is deliberately far shorter than the HTTP timeout, because the two answer
// different questions. A filtered port runs the full read timeout before the
// sweep can conclude anything — 21s per dead host on the default --timeout,
// which is the single largest cost in a roster of mostly-stale names. Whether a
// TCP connect completes is answered in one round trip or not at all, so the
// bound can be tight without shortening the read for a host that is simply slow
// to render.
const sweepConnectTimeout = 3 * time.Second

// sweepTLSTimeout bounds the "does this port speak TLS" handshake, asked only
// for an explicit non-standard port (see resolveSweepScheme). Slightly longer
// than a bare connect because it is a connect plus a handshake.
const sweepTLSTimeout = 5 * time.Second

// sweepScheme is the resolved transport for one schemeless sweep target.
type sweepScheme struct {
	// url is the target rewritten with a concrete scheme and port. Empty when
	// reachable is false.
	url string
	// reachable is false when no port answered a TCP connect, so the sweep can
	// skip the HTTP request entirely instead of paying the read timeout.
	reachable bool
}

// splitSweepTarget breaks a normalized target URL into the parts the resolver
// needs: host, explicit port (empty when the URL carries none) and the path and
// query to carry over.
//
// Its input is always an absolute URL, because every entry point normalizes
// before a phase sees it. Which of those URLs had a scheme the operator
// actually typed is not recoverable from the string — that is what
// Options.TargetsSchemeAssumed records, and what the caller filters on.
func splitSweepTarget(raw string) (host, port, pathAndRest string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "", "", "", false
	}
	rest := u.EscapedPath()
	if u.RawQuery != "" {
		rest += "?" + u.RawQuery
	}
	return u.Hostname(), u.Port(), rest, true
}

// resolveSweepScheme decides which scheme a schemeless target should be probed
// over, and whether it is worth probing at all.
//
// The sweep's contract is one HTTP request per target, and this keeps it: every
// question is answered with a TCP connect (and, in one case, a TLS handshake),
// which is cheaper than a request and carries its own short timeout. What it
// replaces is a guess — schemeless meant http, full stop — that reported every
// https-only host in a target list as dead. Downstream that is not merely a bad
// rank: a host nothing answered for mints no engagement at all, so the host was
// silently dropped from the run.
//
// The rules, and why each is the way round it is:
//
//   - No explicit port: try 80 first, then 443. http-first is what makes the
//     change purely additive — every host that answers today produces a
//     byte-identical record, and the only new traffic goes to hosts currently
//     reported as dead. It also preserves the `http -> 301 -> https` hop that
//     an https-first guess would skip past, which some consumers read as a
//     signal in its own right.
//   - Explicit :443: https, no probe. The port is the operator saying TLS.
//   - Explicit :80: http, no probe. Same, in the other direction. A closed
//     :80 still reaches the request and fails there, as today.
//   - Any other explicit port: a connect cannot tell plaintext from TLS, so
//     ask with a handshake. This is the case a connect alone gets wrong — a
//     TLS service on :8443 accepts the connection and then rejects the
//     plaintext request, which is why it failed in about a second rather than
//     timing out.
func resolveSweepScheme(ctx context.Context, host, port, rest string) sweepScheme {
	build := func(scheme, authority string) string {
		return scheme + "://" + authority + rest
	}
	// The default port is left OFF the rewritten URL: writing it back would
	// turn `example.com` into `http://example.com:80/`, the same endpoint under
	// a different record URL, and the point of trying http first is that a host
	// answering today keeps a byte-identical record.
	explicit := net.JoinHostPort(host, port)

	if port == "" {
		if dialOpen(ctx, host, 80) {
			return sweepScheme{url: build("http", host), reachable: true}
		}
		if dialOpen(ctx, host, 443) {
			return sweepScheme{url: build("https", host), reachable: true}
		}
		return sweepScheme{}
	}

	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return sweepScheme{}
	}
	switch p {
	case 443:
		return sweepScheme{url: build("https", host), reachable: true}
	case 80:
		return sweepScheme{url: build("http", host), reachable: true}
	}

	if !dialOpen(ctx, host, p) {
		return sweepScheme{}
	}
	if info := tlsprobe.Probe(ctx, host, p, sweepTLSTimeout); info != nil && info.ProbeStatus {
		return sweepScheme{url: build("https", explicit), reachable: true}
	}
	return sweepScheme{url: build("http", explicit), reachable: true}
}

// dialOpen reports whether a TCP connect to host:port completes within
// sweepConnectTimeout. A refused, reset, filtered or unresolvable endpoint all
// answer false — the caller only needs "is there something to talk to".
//
// The dialer is a package-level value rather than one per call so the two ports
// a schemeless target may be tried on share it, and portsweep.TCPReachable does
// the connect so the port-sweep phase and this stage cannot end up with two
// answers to the same question.
func dialOpen(ctx context.Context, host string, port int) bool {
	// One timeout, on the context, so cancellation propagates and the dialer
	// does not arm a second timer for the same bound.
	dialCtx, cancel := context.WithTimeout(ctx, sweepConnectTimeout)
	defer cancel()
	return portsweep.TCPReachable(dialCtx, sweepDialer, host, port)
}

// sweepDialer is the connect-probe dialer. Deliberately a plain net.Dialer
// rather than the scan-wide fastdialer: this runs inside prefetchProbeTargets,
// whose whole purpose is to answer per-endpoint questions before the requester
// is used, and fastdialer's value here (DNS caching, deny lists) is either
// already applied upstream — the target list was scope-filtered before the
// phase started — or supplied by the resolution pass alongside this one.
var sweepDialer = &net.Dialer{Timeout: sweepConnectTimeout}

// applyResolvedSchemes rewrites the target list with the schemes the prefetch
// stage resolved, dropping the endpoints nothing answered on.
//
// Dropping rather than letting them fail in the requester is the point of the
// exercise: an unreachable target's HTTP attempt costs a full read timeout, and
// the connect already proved there is nothing there. The caller adds the
// dropped count back into the phase's "attempted" total so the summary still
// reports them as tried-and-silent rather than as never-submitted.
//
// Targets with an explicit scheme, and any the resolver had no opinion about,
// pass through untouched.
func applyResolvedSchemes(targets []string, resolved map[string]sweepScheme) (out []string, dropped int) {
	out = make([]string, 0, len(targets))
	for _, t := range targets {
		r, ok := resolved[t]
		if !ok {
			out = append(out, t)
			continue
		}
		if !r.reachable {
			dropped++
			continue
		}
		out = append(out, r.url)
	}
	return out, dropped
}
