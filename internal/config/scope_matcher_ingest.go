package config

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/storagesig"
)

// ScopeMatchInputFor extracts the scope-relevant fields of a recorded
// request/response pair: the request always, the response when present.
func ScopeMatchInputFor(rr *httpmsg.HttpRequestResponse) ScopeMatchInput {
	input := ScopeMatchInput{
		Host:               rr.Service().Host(),
		Path:               rr.Request().Path(),
		RequestContentType: rr.Request().Header("Content-Type"),
		RequestRaw:         string(rr.Request().Raw()),
	}
	if rr.HasResponse() {
		resp := rr.Response()
		input.StatusCode = resp.StatusCode()
		input.ResponseContentType = resp.Header("Content-Type")
		input.ResponseBody = resp.BodyToString()
	}
	return input
}

// AdmitIngest reports whether a recorded request/response pair should be
// stored. It is the one admit rule every ingest path (REST ingest and proxy,
// CLI ingest, JS extension ingest) applies.
//
// Static files are always filtered, regardless of appliedOnIngest — except
// object-storage assets, kept as metadata-only (body stripped in place) so the
// CDN traversal modules can probe storage-fronted static URLs. The full scope
// rules, judged on the request and the response, apply only when
// appliedOnIngest is set. A nil matcher admits everything.
func (m *ScopeMatcher) AdmitIngest(rr *httpmsg.HttpRequestResponse, appliedOnIngest bool) bool {
	if m == nil {
		return true
	}
	if m.IsStaticFile(rr.Request().Path()) {
		var hg storagesig.HeaderGetter
		if rr.HasResponse() && rr.Response() != nil {
			hg = rr.Response()
		}
		if !storagesig.KeepStaticAsMeta(rr.Request().Path(), hg) {
			return false
		}
		if rr.Response() != nil {
			rr.Response().TruncateBody(0) // metadata-only: keep headers, drop body
		}
	}
	if !appliedOnIngest {
		return true
	}
	return m.InScope(ScopeMatchInputFor(rr))
}
