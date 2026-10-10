// Package requestscheme settles the scheme of a raw HTTP request whose request
// line does not carry one ("a mis-schemed target is loud").
//
// A raw request line is origin-form, so httpmsg.ParseRawRequest infers a
// scheme: absolute-form request line, then a well-known Host port (80/443),
// then a same-origin Origin/Referer, then the https default. That default sent
// every request for a plain-http service on a non-standard port (a dev server
// on :3000, an API on :8080) over TLS, where it failed, and the run reported
// success with no findings.
//
// Settle asks the network when nothing in the request decides: a TCP connect
// plus, on an explicit non-standard port, a TLS handshake
// (portsweep.ResolveScheme, the rules the host sweep uses for schemeless
// targets). It is the one implementation `vigolium scan-request` and
// POST /api/scan-request share; each caller decides what to tell its operator
// from the returned Result. ParseRawRequest itself is unchanged: it is shared
// with ingest and Burp import, where no probe is acceptable.
package requestscheme

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/portsweep"
)

// scheme_source values: what decided the scheme of a scanned request. They are
// reported on the scan-url / scan-request result and the REST response.
const (
	SourceExplicit = "explicit" // a target URL override, absolute-form request line, curl URL
	SourcePort     = "port"     // Host :80 / :443
	SourceOrigin   = "origin"   // same-origin Origin header
	SourceReferer  = "referer"  // same-origin Referer header
	SourceProbe    = "probe"    // a connect / TLS handshake answered
	SourceDefault  = "default"  // nothing settled it; https assumed
)

// Resolver is the network question behind the probe (portsweep.ResolveScheme).
type Resolver func(ctx context.Context, host, port, rest string, opts portsweep.SchemeOptions) portsweep.SchemeResolution

// Options tunes Settle.
type Options struct {
	// Pinned: the caller overrode the target URL (-t, target_url), so the
	// request already carries the operator's scheme and is never probed.
	Pinned bool
	// NoProbe keeps the inferred https default without contacting the target
	// (--no-scheme-probe, no_scheme_probe; also a scope-refused target).
	NoProbe bool
	// Resolver replaces portsweep.ResolveScheme (tests). Nil = the real probe.
	Resolver Resolver
}

// Result is a settled request and what settled it.
type Result struct {
	// Request is the request to scan: the input, or a rebuild of it when the
	// probe chose a different scheme or port.
	Request *httpmsg.HttpRequestResponse
	// Source is one of the Source* values ("" for a nil request).
	Source string
	// Header is the header that decided an origin/referer Source, as written
	// ("Origin", "Referer").
	Header string
	// Scheme is the scheme the request is sent with.
	Scheme string
	// Host and Port are the Host header's hostname and explicit port (Port is
	// "" when the header names none).
	Host, Port string
	// Authority is host:port of the inferred service (before any probe).
	Authority string
	// ProbedAuthority is host:port the probe settled (Source probe only).
	ProbedAuthority string
	// Changed reports that Request differs from the input request.
	Changed bool
}

// ExplicitPort reports whether the Host header named a port.
func (r Result) ExplicitPort() bool { return r.Port != "" }

// Settle returns the request to scan and what decided its scheme. raw is the
// normalized raw request the input was parsed from; "" (a curl command, which
// carries its URL) is explicit, as is a pinned request.
func Settle(ctx context.Context, raw string, rr *httpmsg.HttpRequestResponse, opts Options) Result {
	res := Result{Request: rr}
	if rr != nil && rr.Service() != nil {
		res.Scheme = rr.Service().Protocol()
	}
	if raw == "" || opts.Pinned {
		res.Source = SourceExplicit
		return res
	}
	if rr == nil || rr.Service() == nil {
		return res
	}
	if RequestLineHasScheme(raw) {
		res.Source = SourceExplicit
		return res
	}
	host, port, ok := HostPort(raw)
	if !ok {
		res.Source = SourceDefault
		return res
	}
	res.Host, res.Port = host, port
	if port == "80" || port == "443" {
		res.Source = SourcePort
		return res
	}
	svc := rr.Service()
	res.Authority = net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
	// The same port the parser matched the header against: the Host's own,
	// or 0 (host-only) when it named none.
	headerPort := 0
	if port != "" {
		headerPort = svc.Port()
	}
	if _, header, ok := httpmsg.OriginRefererScheme(raw, svc.Host(), headerPort); ok {
		res.Header = header
		res.Source = strings.ToLower(header)
		return res
	}

	res.Source = SourceDefault
	if opts.NoProbe {
		return res
	}
	resolve := opts.Resolver
	if resolve == nil {
		resolve = portsweep.ResolveScheme
	}
	probe := resolve(ctx, host, port, "", portsweep.SchemeOptions{PreferTLS: true})
	if !probe.Reachable {
		// Nothing answered: keep the inferred URL.
		return res
	}
	resolvedPort := port
	if resolvedPort == "" {
		resolvedPort = "443"
		if probe.Scheme == "http" {
			resolvedPort = "80"
		}
	}
	probed := net.JoinHostPort(host, resolvedPort)
	if probe.Scheme != svc.Protocol() || resolvedPort != strconv.Itoa(svc.Port()) {
		rebuilt, err := httpmsg.ParseRawRequestWithURL(raw, probe.Scheme+"://"+probed)
		if err != nil {
			return res
		}
		res.Request, res.Changed = rebuilt, true
	}
	res.Source, res.Scheme, res.ProbedAuthority = SourceProbe, probe.Scheme, probed
	return res
}

// RequestLineHasScheme reports whether the request line uses absolute-form (an
// explicit http(s):// on the request target), in which case the scheme is
// already pinned and needs no inference.
func RequestLineHasScheme(raw string) bool {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := strings.ToLower(fields[1])
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

// HostPort returns the Host header's hostname and explicit port ("" when the
// header names none).
func HostPort(raw string) (host, port string, ok bool) {
	head := raw
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "\n\n"); i >= 0 {
		head = head[:i]
	}
	lines := strings.Split(head, "\n")
	for _, line := range lines[1:] {
		name, value, cut := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !cut || !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		value = strings.TrimSpace(value)
		if h, p, err := net.SplitHostPort(value); err == nil {
			return h, p, h != ""
		}
		return strings.Trim(value, "[]"), "", value != ""
	}
	return "", "", false
}
