package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scan-request scheme resolution ("a mis-schemed target is loud").
//
// A raw request line is origin-form — it carries no scheme — so
// httpmsg.ParseRawRequest infers one: absolute-form request line, then a
// well-known Host port (80/443), then a same-origin Origin/Referer, then the
// https default. That default sent every request for a plain-http service on a
// non-standard port (a dev server on :3000, an API on :8080) over TLS, where it
// failed, and the run reported success with no findings.
//
// When nothing in the request settles it, scan-request now asks the network:
// a TCP connect plus, on an explicit non-standard port, a TLS handshake
// (portsweep.ResolveScheme — the same rules the host sweep uses for schemeless
// targets). ParseRawRequest itself is unchanged: it is shared with ingest, the
// server and Burp import, where no probe is acceptable.

// scheme_source values on the scan-url / scan-request result.
const (
	schemeSourceExplicit = "explicit" // -t, absolute-form request line, curl URL
	schemeSourcePort     = "port"     // Host :80 / :443
	schemeSourceOrigin   = "origin"   // same-origin Origin header
	schemeSourceReferer  = "referer"  // same-origin Referer header
	schemeSourceProbe    = "probe"    // a connect / TLS handshake answered
	schemeSourceDefault  = "default"  // nothing settled it; https assumed
)

// scanReqNoSchemeProbe is --no-scheme-probe: keep the inferred https default
// without contacting the target first.
var scanReqNoSchemeProbe bool

// requestSchemeResolver is the network question behind the probe; a variable so
// tests can assert when it is (not) asked.
var requestSchemeResolver = portsweep.ResolveScheme

// requestHostPort returns the Host header's hostname and explicit port ("" when
// the header names none).
func requestHostPort(raw string) (host, port string, ok bool) {
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

// settleRequestScheme returns the request to scan and its scheme_source. A
// curl command (normalized == "") or a -t override (pinned) carries its scheme
// and is never probed; a raw request goes through resolveRequestScheme.
func settleRequestScheme(ctx context.Context, normalized string, rr *httpmsg.HttpRequestResponse, pinned, noProbe bool) (*httpmsg.HttpRequestResponse, string) {
	if normalized == "" || pinned {
		return rr, schemeSourceExplicit
	}
	return resolveRequestScheme(ctx, normalized, rr, noProbe)
}

// resolveRequestScheme settles the scheme of a raw request parsed without -t
// and returns the request to scan (rebuilt when the probe chose http) with its
// scheme_source. It also prints the stderr heads-up the inference used to
// print, now naming what decided it.
func resolveRequestScheme(ctx context.Context, normalized string, rr *httpmsg.HttpRequestResponse, noProbe bool) (*httpmsg.HttpRequestResponse, string) {
	if rr == nil || rr.Service() == nil {
		return rr, ""
	}
	if requestLineHasScheme(normalized) {
		return rr, schemeSourceExplicit
	}
	host, port, ok := requestHostPort(normalized)
	if !ok {
		return rr, schemeSourceDefault
	}
	if port == "80" || port == "443" {
		return rr, schemeSourcePort
	}
	svc := rr.Service()
	authority := net.JoinHostPort(svc.Host(), fmt.Sprintf("%d", svc.Port()))
	// The same port the parser matched the header against: the Host's own,
	// or 0 (host-only) when it named none.
	headerPort := 0
	if port != "" {
		headerPort = svc.Port()
	}
	if s, header, ok := httpmsg.OriginRefererScheme(normalized, svc.Host(), headerPort); ok {
		if port != "" {
			fmt.Fprintf(os.Stderr, "%s request line has no scheme — inferred %s from the %s header; sending to %s\n",
				terminal.WarnPrefix(), terminal.BoldYellow(s+"://"), header, terminal.Cyan(rr.Target()))
			fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (use %s to force TLS)\n",
				terminal.BoldCyan("-t "+s+"://"+authority), terminal.Cyan("https://"))
		}
		return rr, strings.ToLower(header)
	}

	if noProbe {
		warnDefaultScheme(rr, authority, port != "")
		return rr, schemeSourceDefault
	}
	res := requestSchemeResolver(ctx, host, port, "", portsweep.SchemeOptions{PreferTLS: true})
	if !res.Reachable {
		// Nothing answered: keep the inferred URL. The unreachable result says
		// so, with the -t hint (schemeHint).
		warnDefaultScheme(rr, authority, port != "")
		return rr, schemeSourceDefault
	}
	resolvedPort := port
	if resolvedPort == "" {
		resolvedPort = "443"
		if res.Scheme == "http" {
			resolvedPort = "80"
		}
	}
	out := rr
	if res.Scheme != svc.Protocol() || resolvedPort != fmt.Sprintf("%d", svc.Port()) {
		rebuilt, err := httpmsg.ParseRawRequestWithURL(normalized, res.Scheme+"://"+net.JoinHostPort(host, resolvedPort))
		if err != nil {
			warnDefaultScheme(rr, authority, port != "")
			return rr, schemeSourceDefault
		}
		out = rebuilt
	}
	// A portless Host that answered TLS is the old default confirmed: say
	// nothing, as before. Anything else changed or settled a genuinely
	// ambiguous choice, which the operator should see.
	if port != "" || res.Scheme != "https" {
		what := "plain HTTP"
		if res.Scheme == "https" {
			what = "TLS"
		}
		fmt.Fprintf(os.Stderr, "%s request line has no scheme and no Origin/Referer — probed %s: %s; sending to %s\n",
			terminal.WarnPrefix(), terminal.Cyan(net.JoinHostPort(host, resolvedPort)), what, terminal.Cyan(out.Target()))
		fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (or %s to skip the probe)\n",
			terminal.BoldCyan("-t "+res.Scheme+"://"+net.JoinHostPort(host, resolvedPort)), terminal.Cyan("--no-scheme-probe"))
	}
	return out, schemeSourceProbe
}

// warnDefaultScheme is the heads-up for the https default on a non-standard
// port (a portless Host keeps the old silent default).
func warnDefaultScheme(rr *httpmsg.HttpRequestResponse, authority string, explicitPort bool) {
	if !explicitPort {
		return
	}
	fmt.Fprintf(os.Stderr, "%s request line has no scheme and no Origin/Referer to infer from — defaulting to %s; sending to %s\n",
		terminal.WarnPrefix(), terminal.BoldYellow("https://"), terminal.Cyan(rr.Target()))
	fmt.Fprintf(os.Stderr, "  if the target is plain http, pass %s\n",
		terminal.BoldCyan("-t http://"+authority))
}
