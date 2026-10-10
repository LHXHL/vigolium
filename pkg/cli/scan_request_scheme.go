package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/requestscheme"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scan-request scheme resolution ("a mis-schemed target is loud"). The rules
// live in pkg/requestscheme, shared with POST /api/scan-request; this file
// adds the CLI's stderr heads-ups.

// scheme_source values on the scan-url / scan-request result.
const (
	schemeSourceExplicit = requestscheme.SourceExplicit
	schemeSourcePort     = requestscheme.SourcePort
	schemeSourceOrigin   = requestscheme.SourceOrigin
	schemeSourceReferer  = requestscheme.SourceReferer
	schemeSourceProbe    = requestscheme.SourceProbe
	schemeSourceDefault  = requestscheme.SourceDefault
)

// scanReqNoSchemeProbe is --no-scheme-probe: keep the inferred https default
// without contacting the target first.
var scanReqNoSchemeProbe bool

// requestSchemeResolver is the network question behind the probe; a variable so
// tests can assert when it is (not) asked.
var requestSchemeResolver requestscheme.Resolver = portsweep.ResolveScheme

// settleRequestScheme returns the request to scan and its scheme_source. A
// curl command (normalized == "") or a -t override (pinned) carries its scheme
// and is never probed; a raw request is settled by requestscheme.Settle, and
// the stderr heads-up the inference used to print now names what decided it.
func settleRequestScheme(ctx context.Context, normalized string, rr *httpmsg.HttpRequestResponse, pinned, noProbe bool) (*httpmsg.HttpRequestResponse, string) {
	res := requestscheme.Settle(ctx, normalized, rr, requestscheme.Options{
		Pinned:   pinned,
		NoProbe:  noProbe,
		Resolver: requestSchemeResolver,
	})
	switch res.Source {
	case schemeSourceOrigin, schemeSourceReferer:
		if res.ExplicitPort() {
			fmt.Fprintf(os.Stderr, "%s request line has no scheme — inferred %s from the %s header; sending to %s\n",
				terminal.WarnPrefix(), terminal.BoldYellow(res.Scheme+"://"), res.Header, terminal.Cyan(res.Request.Target()))
			fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (use %s to force TLS)\n",
				terminal.BoldCyan("-t "+res.Scheme+"://"+res.Authority), terminal.Cyan("https://"))
		}
	case schemeSourceDefault:
		// Nothing answered, or the probe was off: keep the inferred URL. The
		// unreachable result says so, with the -t hint (schemeHint).
		if res.Authority != "" {
			warnDefaultScheme(res.Request, res.Authority, res.ExplicitPort())
		}
	case schemeSourceProbe:
		// A portless Host that answered TLS is the old default confirmed: say
		// nothing, as before. Anything else changed or settled a genuinely
		// ambiguous choice, which the operator should see.
		if res.ExplicitPort() || res.Scheme != "https" {
			what := "plain HTTP"
			if res.Scheme == "https" {
				what = "TLS"
			}
			fmt.Fprintf(os.Stderr, "%s request line has no scheme and no Origin/Referer — probed %s: %s; sending to %s\n",
				terminal.WarnPrefix(), terminal.Cyan(res.ProbedAuthority), what, terminal.Cyan(res.Request.Target()))
			fmt.Fprintf(os.Stderr, "  pass %s to pin the scheme (or %s to skip the probe)\n",
				terminal.BoldCyan("-t "+res.Scheme+"://"+res.ProbedAuthority), terminal.Cyan("--no-scheme-probe"))
		}
	}
	return res.Request, res.Source
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
