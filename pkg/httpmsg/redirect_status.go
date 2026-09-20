package httpmsg

import nethttp "net/http"

// IsRedirectStatus reports whether a status code is one that carries a
// Location, i.e. names a destination.
//
// 304 is excluded: it is a cache validator, not a redirect, and has no
// destination to show. 300/305/306 are included because they are 3xx with a
// Location; none is seen in practice, and excluding them by hand is how a
// second, subtly different spelling of "redirect" gets written.
//
// It lives here because every layer that asks needs the same answer: the
// transport's chain handling, the executor's chain_truncated write, discovery's
// redirect detector, and the stored-record read path that renders chains. Four
// packages previously carried four spellings of this switch, which is the
// mechanism by which a write path and the read path rendering it come to
// disagree — a disagreement whose symptom is a blank destination, not an error.
func IsRedirectStatus(code int) bool {
	return code >= 300 && code < 400 && code != nethttp.StatusNotModified
}
