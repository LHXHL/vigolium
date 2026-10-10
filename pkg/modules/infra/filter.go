package infra

import (
	"strings"
	"unicode"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Is2xx reports whether status is an HTTP 2xx success code. Shared by the modules
// whose differential/boolean legs require a genuine 2xx content difference rather
// than a status flip (a 3xx redirect, 4xx rejection, or 5xx error is not the query
// result or resource reacting).
func Is2xx(status int) bool { return status >= 200 && status < 300 }

// IsValidForInjectionVulns checks if the URL is valid for injection vulnerability testing.
// Rejects media/JS URLs, OPTIONS/CONNECT methods, and CDN-edge infrastructure paths.
func IsValidForInjectionVulns(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse) bool {
	if utils.IsMediaAndJSURL(urlx.Path) || ctx.Request().Method() == "OPTIONS" || ctx.Request().Method() == "CONNECT" {
		return false
	}
	if IsCDNInfraPath(urlx.Path) {
		return false
	}
	return true
}

// IsCDNInfraPath reports whether path lives under a CDN/edge-provider's reserved
// namespace — served entirely by the edge (Cloudflare, etc.), never routed to the
// origin application. Cloudflare's `/cdn-cgi/` prefix hosts bot-challenge, RUM,
// email-decode and trace endpoints whose bodies are opaque, per-request, encrypted
// blobs; probing them for injection is meaningless and the non-deterministic
// responses fool boolean/timing oracles (the evr-kr.acme.com /cdn-cgi/challenge-
// platform XPath false positive). No application injection sink ever lives here, so
// injection modules skip these paths wholesale.
func IsCDNInfraPath(path string) bool {
	p := strings.ToLower(path)
	return strings.HasPrefix(p, "/cdn-cgi/") || p == "/cdn-cgi"
}

// urlParamNames are parameter-name fragments that suggest the value is a URL the
// server may fetch or redirect to. They are long and distinctive enough to match
// as substrings anywhere in the name (`imageUrl`, `redirect_uri`, `webhookTarget`).
// Package-level so it is allocated once, not per call.
//
// Names that are already covered by a shorter fragment are deliberately absent:
// `origin_url`/`returnurl` contain "url" and `uri_template` contains "uri".
var urlParamNames = []string{
	"url", "uri", "link", "src", "href", "dest", "redirect",
	"path", "file", "page", "target", "callback", "endpoint",
	"resource", "fetch", "load", "proxy", "request",
	// Blind-SSRF sinks: webhooks, media/avatar importers, feed readers, and
	// post-login continuation targets.
	"webhook", "avatar", "continue", "domain",
}

// urlParamTokens are short or ambiguous name fragments that only qualify a
// parameter when they appear as a whole token of the name (see paramNameTokens),
// never as a substring: `host` must not match `ghost`, `next` must not match
// `context`, `to` must not match `token`/`photo`, `out` must not match
// `timeout`/`layout`, `logo` must not match `logout`, and `feed` must not match
// `feedback`.
var urlParamTokens = map[string]bool{
	"hook": true, "image": true, "img": true, "icon": true, "logo": true,
	"feed": true, "next": true, "return": true, "host": true, "site": true,
	"out": true, "to": true,
}

// ParamNameTokens is the exported form of paramNameTokens, for modules that
// gate on whole name tokens (password_reset_poisoning, redos_probe) rather
// than substrings.
func ParamNameTokens(name string) []string { return paramNameTokens(name) }

// paramNameTokens splits a parameter name into lower-case word tokens on
// non-alphanumeric separators (`_`, `-`, `.`, `[`, …), camelCase humps,
// acronym boundaries (`returnURLPath` → return, url, path) and letter/digit
// boundaries (`img2` → img, 2).
func paramNameTokens(name string) []string {
	var tokens []string
	runes := []rune(name)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			tokens = append(tokens, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := runes[i-1]
		switch {
		case unicode.IsDigit(r) != unicode.IsDigit(prev):
			flush(i)
			start = i
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			// camelCase hump: returnUrl → return | Url
			flush(i)
			start = i
		case unicode.IsLower(r) && unicode.IsUpper(prev) && i-1 > start:
			// acronym end: URLPath → URL | Path (split before the P)
			flush(i - 1)
			start = i - 1
		}
	}
	flush(len(runes))
	return tokens
}

// standardRequestHeaders are fixed HTTP request headers a browser or client always
// sends. None is a server-side URL-fetch/injection sink, yet the name/value
// heuristics below otherwise qualify some of them: `Upgrade-Insecure-Requests`
// substring-matches "request", and `Referer`/`Origin` carry a URL value. Injecting
// an internal URL into any of these does not make the server fetch it — it only
// perturbs the app's redirect/CSRF/content-negotiation logic, whose response
// differential is then misread as SSRF (the fcworkflow.acme.com Referer /
// Upgrade-Insecure-Requests false positives). Each is a fixed protocol/browser
// header, not an application parameter, so excluding it by exact name is safe;
// genuine header SSRF sinks (X-Forwarded-*, X-Original-URL, Forwarded, …) are custom
// headers and are deliberately absent here.
var standardRequestHeaders = map[string]bool{
	"referer": true, "referrer": true, "origin": true,
	"upgrade-insecure-requests": true, "user-agent": true,
	"accept": true, "accept-language": true, "accept-encoding": true,
	"accept-charset": true, "cache-control": true, "pragma": true,
	"connection": true, "cookie": true, "host": true, "dnt": true,
	"te": true, "priority": true, "content-type": true, "content-length": true,
	"x-requested-with": true, "from": true, "via": true, "range": true,
	"if-modified-since": true, "if-none-match": true, "max-forwards": true,
	"sec-fetch-dest": true, "sec-fetch-mode": true, "sec-fetch-site": true,
	"sec-fetch-user": true, "sec-ch-ua": true, "sec-ch-ua-mobile": true,
	"sec-ch-ua-platform": true,
}

// IsStandardRequestHeader reports whether name (case-insensitive) is a fixed
// standard HTTP request header that is never an application URL-fetch/injection
// sink. Insertion-point gates use it to avoid mis-scoping a scan onto a browser
// header whose URL-like name or value would otherwise qualify it.
func IsStandardRequestHeader(name string) bool {
	return standardRequestHeaders[strings.ToLower(name)]
}

// LooksLikeURLParam reports whether a parameter — by its name or its current
// value — looks like it accepts a URL. Shared by the SSRF / SSRF-bypass modules
// so they target the same parameter surface.
//
// It does not know where the parameter lives, so a name that is also a fixed
// standard request header (`host`, `origin`, `from`, …) is always excluded. Callers
// holding an insertion point should use LooksLikeURLParamAt, which applies that
// exclusion to header insertion points only, so a `?host=` query parameter still
// qualifies.
func LooksLikeURLParam(name, value string) bool {
	return LooksLikeURLParamAt(httpmsg.INS_HEADER, name, value)
}

// LooksLikeURLParamAt is LooksLikeURLParam for a parameter of a known insertion
// point type. The standard-request-header exclusion applies only to INS_HEADER:
// a fixed browser header is never a fetch sink, however URL-like its name or
// value looks, while a query/body/JSON parameter that merely shares a header's
// name (`host`, `origin`) is an ordinary application parameter.
func LooksLikeURLParamAt(typ httpmsg.InsertionPointType, name, value string) bool {
	nameLower := strings.ToLower(name)
	if typ == httpmsg.INS_HEADER && standardRequestHeaders[nameLower] {
		return false
	}
	for _, n := range urlParamNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}
	for _, tok := range paramNameTokens(name) {
		if urlParamTokens[tok] {
			return true
		}
	}
	return strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "//")
}
