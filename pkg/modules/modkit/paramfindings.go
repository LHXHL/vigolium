package modkit

import (
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// ParamFindingKey returns the location half of a ParameterFindingRegistry key
// for item: "scheme://host/path" with the host lowercased and an empty path
// normalized to "/". The query string is not part of the key, so every
// request to the same endpoint shares one key per parameter.
//
// The executor (dispatch-time skip and post-emit MarkFound) and modules
// (ScanContext.ParamAlreadyFound / MarkParamFound) must key the registry
// identically or their marks never meet. Use this helper, or the ScanContext
// methods built on it, instead of composing a key by hand.
func ParamFindingKey(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if urlx, err := item.URL(); err == nil && urlx != nil {
		return normalizeParamFindingLocation(urlx.Scheme, urlx.Host, urlx.Path)
	}
	if item.Request() != nil {
		host, _ := httpmsg.GetHeaderValue(item.Request().Raw(), "Host")
		return normalizeParamFindingLocation("", host, item.Request().Path())
	}
	return ""
}

// ParamFindingKeyFromResult returns the registry location key for an emitted
// finding, using the same normalization as ParamFindingKey. It prefers the
// result URL, then Matched, then the raw request's Host header and path.
func ParamFindingKeyFromResult(result *output.ResultEvent) string {
	if result == nil {
		return ""
	}
	if result.URL != "" {
		if parsed, err := url.Parse(result.URL); err == nil {
			return normalizeParamFindingLocation(parsed.Scheme, parsed.Host, parsed.Path)
		}
	}
	if result.Matched != "" {
		if parsed, err := url.Parse(result.Matched); err == nil && parsed.Host != "" {
			return normalizeParamFindingLocation(parsed.Scheme, parsed.Host, parsed.Path)
		}
	}
	if result.Request != "" {
		host, _ := httpmsg.GetHeaderValue([]byte(result.Request), "Host")
		path, _ := httpmsg.GetPath([]byte(result.Request))
		return normalizeParamFindingLocation(result.Scheme, host, path)
	}
	return normalizeParamFindingLocation(result.Scheme, result.Host, "")
}

func normalizeParamFindingLocation(scheme, host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	// Raw-request fallbacks hand over the request-target, query included.
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if scheme == "" {
		return host + path
	}
	return strings.ToLower(scheme) + "://" + host + path
}

// ParamDedupEnabled reports whether cross-module (param, vuln-class) dedup is
// active: a registry is wired and the operator did not pass --no-param-dedup.
// nil-safe (false).
func (sc *ScanContext) ParamDedupEnabled() bool {
	return sc != nil && sc.ParamFindings != nil && !sc.NoParamDedup
}

// ParamAlreadyFound reports whether a finding of vulnClass was already
// recorded for paramName at item's location (by any module, or by the
// executor after an emit). Request-scope modules call it at the top of their
// per-insertion-point loop and skip the point when it returns true. Always
// false when dedup is disabled or vulnClass is empty.
func (sc *ScanContext) ParamAlreadyFound(item *httpmsg.HttpRequestResponse, paramName, vulnClass string) bool {
	if vulnClass == "" || !sc.ParamDedupEnabled() {
		return false
	}
	return sc.ParamFindings.HasFinding(ParamFindingKey(item), paramName, vulnClass)
}

// MarkParamFound records a finding of vulnClass for paramName at item's
// location. The executor already marks every emitted finding that carries a
// FuzzingParameter; modules call this only when their finding's URL differs
// from the scanned item's (e.g. a stored-XSS render page) or when they want
// the mark visible before their results are processed. No-op when dedup is
// disabled or vulnClass/paramName is empty.
func (sc *ScanContext) MarkParamFound(item *httpmsg.HttpRequestResponse, paramName, vulnClass string) {
	if vulnClass == "" || paramName == "" || !sc.ParamDedupEnabled() {
		return
	}
	sc.ParamFindings.MarkFound(ParamFindingKey(item), paramName, vulnClass)
}
