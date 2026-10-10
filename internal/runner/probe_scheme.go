package runner

import (
	"context"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/portsweep"
)

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
// question is answered with a TCP connect (and, for an explicit non-standard
// port, a TLS handshake), which is cheaper than a request and carries its own
// short timeout. What it replaces is a guess — schemeless meant http, full stop
// — that reported every https-only host in a target list as dead. Downstream
// that is not merely a bad rank: a host nothing answered for mints no
// engagement at all, so the host was silently dropped from the run.
//
// The rules live in portsweep.ResolveScheme, shared with scan-request's scheme
// probe so the two cannot disagree. The sweep keeps http first for a target
// with no port: every host that answers today produces a byte-identical record,
// and the `http -> 301 -> https` hop an https-first guess would skip past is a
// signal some consumers read in its own right.
func resolveSweepScheme(ctx context.Context, host, port, rest string) sweepScheme {
	res := portsweep.ResolveScheme(ctx, host, port, rest, portsweep.SchemeOptions{})
	return sweepScheme{url: res.URL, reachable: res.Reachable}
}

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
