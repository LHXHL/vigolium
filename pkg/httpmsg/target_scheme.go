package httpmsg

import "strings"

// DefaultTargetScheme is the scheme a schemeless scan target is read as. http
// keeps the normalized form byte-identical to the request GetRawRequestFromURL
// already built for a bare host, so nothing that works today changes shape.
const DefaultTargetScheme = "http"

// EnsureURLScheme prefixes a schemeless target with defaultScheme so callers all
// hand the rest of the pipeline the same absolute URL. A target that already
// names a scheme is returned untouched, whatever that scheme is.
//
// It exists because "does this target have a scheme" has three different answers
// scattered around the tree, and only one of them is right. The HTTP phases
// never had to ask: urlutil.ParseAbsoluteURL accepts a bare host and
// GetRawRequestFromURL defaults the service protocol to http, so `-t example.com`
// or a -T file of bare hostnames sweeps fine under probe, discovery and
// known-issue-scan. The browser phase does have to ask -- spitolas parses its
// seed with net/url, where "example.com" is a path with no host ("target URL
// must have a host") and "example.com:8443" is worse still ("first path segment
// in URL cannot contain colon") -- so spidering hard-failed per target on the
// exact host lists the other phases scanned, and because it reports a failed
// crawl as a completed one with 0 records, `scan --only spidering --soft-fail`
// exited 0 with an empty export.
//
// The default scheme is the caller's to choose because it is not the same
// everywhere: scan targets take http, so the normalized form stays
// byte-identical to the request the HTTP path already built for them (a host
// that only answers on 443 redirects there on the first hop), while a shim
// translating a tool that documents bare domains takes https.
func EnsureURLScheme(target, defaultScheme string) string {
	if target == "" {
		return target
	}
	// A scheme only counts when "://" comes before any path, query or fragment;
	// otherwise a schemeless "host/r?u=http://x" would look like it had one.
	if i := strings.Index(target, "://"); i > 0 && !strings.ContainsAny(target[:i], "/?#") {
		return target
	}
	// TrimPrefix keeps a protocol-relative "//example.com" to one separator.
	return defaultScheme + "://" + strings.TrimPrefix(target, "//")
}
