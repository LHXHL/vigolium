package database

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// IsRedirectStatus reports whether a status code is one that carries a Location.
//
// 304 is excluded: it is a cache validator, not a redirect, and has no
// destination to show. Shared so the write path (which decides what to store in
// response_location) and the read path (which decides what to render) can never
// disagree about what counts as a redirect — a disagreement whose symptom is a
// blank destination rather than an error.
func IsRedirectStatus(code int) bool {
	return httpmsg.IsRedirectStatus(code)
}

// RedirectLocation returns where this record's response points, or "" when it is
// not a redirect and when the destination is not recoverable.
//
// The stored column answers first. Parsing raw_response is the fallback for
// records written before response_location existed, whose column is empty
// whether or not the response carried a Location — the two are
// indistinguishable, so a legacy redirect with no Location costs one parse of
// bytes already in hand.
//
// It lives here, beside the write path that fills the column, so the question
// "where does this redirect go" has ONE answer. The read path used to carry its
// own copy of the parse, which is exactly the drift this file exists to prevent.
func (r *HTTPRecord) RedirectLocation() string {
	if r == nil || !IsRedirectStatus(r.StatusCode) {
		return ""
	}
	if r.ResponseLocation != "" {
		return r.ResponseLocation
	}
	return redirectLocationFromRaw(r.StatusCode, r.RawResponse)
}

// redirectLocationFromRaw extracts the Location header a redirect response
// carries, or "" when the status is not a redirect, the bytes are absent, or no
// such header is present.
//
// It takes the raw bytes rather than a parsed response so every response-
// mutation path can call it with whatever it is about to write, which is what
// keeps the stored destination consistent with the stored response: a replayed
// or backfilled redirect that updated raw_response without updating this column
// would keep pointing at the destination it used to have.
func redirectLocationFromRaw(statusCode int, raw []byte) string {
	if !IsRedirectStatus(statusCode) || len(raw) == 0 {
		return ""
	}
	loc, err := httpmsg.GetHeaderValue(raw, "Location")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(loc)
}
