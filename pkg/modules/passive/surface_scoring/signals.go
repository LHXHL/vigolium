package surface_scoring

import (
	"math/bits"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/dashboardsig"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Signal is one bit of attack-surface evidence. The score is the popcount of the
// set bits times pointsPerSignal, so every signal is worth the same and the
// score is reproducible from the record alone.
type Signal uint16

const (
	// -- Input surface: can an active module act on this record at all? --

	// SignalHasInput — the request carries client-supplied input (a query string
	// or a body). A record with none is unattackable by most of the active fleet
	// however rich its response, which makes this the strongest single predictor
	// in the set.
	SignalHasInput Signal = 1 << iota
	// SignalStateChanging — a method that mutates (POST/PUT/PATCH/DELETE).
	// Drives access-control, CSRF and mass-assignment surface.
	SignalStateChanging
	// SignalUpload — the request is a file upload (multipart) or the response
	// offers one (a file input). Its own vulnerability class.
	SignalUpload

	// -- Context: does the stack or auth posture raise the odds? --

	// SignalTechStack — the host has at least one detected technology stack.
	// Host-scoped, so it is resolved at flush rather than per record (see Module).
	SignalTechStack
	// SignalLegacyStack — the path ends in a server-executed extension of an
	// older generation (.php, .jsp, .do, .aspx, .cgi…). These map a file
	// directly to a handler, predate framework-level defaults, and are what the
	// Struts/PHP/ASP.NET module families exist for.
	SignalLegacyStack
	// SignalAuthBearing — the exchange carries identity: an Authorization
	// header, a request Cookie, or a response Set-Cookie. Access-control and
	// IDOR bugs live on records that carry a session.
	SignalAuthBearing

	// -- Shape: what does the response look like? --

	// SignalRichHTML — an HTML document carrying interactive or navigational
	// substance (form inputs, or a real set of links).
	SignalRichHTML
	// SignalSPA — the response is a single-page-app shell.
	SignalSPA
	// SignalJSON — the response body is JSON.
	SignalJSON
	// SignalResponsive — the application answered: not a WAF/CDN edge block, and
	// either a success status or an error verbose enough to leak a stack trace.
	SignalResponsive
)

// pointsPerSignal converts the bitmask to the stored 0-100 score.
//
// Ten signals at ten points each is chosen so a stored score reads back as a
// signal count (score/10), which a weighted scheme would cost and a clamped
// 20-point scheme would destroy at the top of the range — every record with five
// or more signals would read 100, flattening exactly the band that matters.
// Adding an eleventh signal is therefore not free: it needs this constant, the
// ceiling, and the documented meaning of a score revisited together.
const pointsPerSignal = 10

// richHTMLMinAnchors is how many <a > tags an HTML document needs to count as
// navigationally rich when it carries no form inputs. A single "back to home"
// link is not surface; a nav bar is.
const richHTMLMinAnchors = 5

// legacyHandlerExtensions are path extensions that name a server-executed
// handler from an older application generation. Deliberately NOT included:
// .js/.ts (client-side), .html/.htm (static), and .json/.xml (data), none of
// which imply a server-side execution model. Mirrors the shape of
// modkit.HasStaticAssetExtension.
var legacyHandlerExtensions = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".phtm", ".phtml", ".phps",
	".asp", ".aspx", ".asmx", ".ashx", ".axd",
	".jsp", ".jspx", ".jspa", ".jsf", ".do", ".action",
	".cfm", ".cfml",
	".cgi", ".pl", ".shtml",
}

// legacyHandlerPathInfoPrefixes is legacyHandlerExtensions with a trailing
// slash, for the PATH_INFO form (/index.php/users/1). Built once: concatenating
// inside the match loop cost 24 throwaway allocations on every record scanned.
var legacyHandlerPathInfoPrefixes = func() []string {
	out := make([]string, len(legacyHandlerExtensions))
	for i, ext := range legacyHandlerExtensions {
		out[i] = ext + "/"
	}
	return out
}()

// Score converts a signal bitmask to the stored surface score.
func (s Signal) Score() int {
	return bits.OnesCount16(uint16(s)) * pointsPerSignal
}

// recordSignals computes the signals derivable from the record itself. The
// host-scoped SignalTechStack is deliberately NOT computed here: under
// ParallelPassive every eligible passive module for one record runs
// concurrently, so reading the tech registry at this point races the very
// fingerprint module that would populate it. Returns 0 when there is no
// response, which cannot earn any signal.
func recordSignals(item *httpmsg.HttpRequestResponse, host string, scanCtx *modkit.ScanContext) Signal {
	if item == nil {
		return 0
	}
	req := item.Request()
	resp := item.Response()
	if req == nil || resp == nil {
		return 0
	}

	var out Signal

	// -- request-derived (cheap, no body work) --

	if hasClientInput(req) {
		out |= SignalHasInput
	}
	if isStateChanging(req.Method()) {
		out |= SignalStateChanging
	}
	if hasLegacyHandlerExtension(req.Path()) {
		out |= SignalLegacyStack
	}
	if isAuthBearing(req, resp) {
		out |= SignalAuthBearing
	}
	if isMultipartRequest(req) {
		out |= SignalUpload
	}

	// -- response-derived --

	class := modkit.ResponseContentClass(item)
	if class == modkit.ContentClassUnknown {
		// The record's own Content-Type is indeterminate — fall back to the host's
		// root class, the same two-tier resolution the executor's content-class
		// gate uses (see Executor.passesContentClassFilter). Resolved here rather
		// than by the caller because it is an LRU lookup under a lock and this
		// branch is the minority: most records carry a usable Content-Type.
		class = scanCtx.ContentClass.Get(host)
	}

	if isResponsive(resp) {
		out |= SignalResponsive
	}

	if class == modkit.ContentClassJSON {
		return out | SignalJSON
	}

	// Every remaining signal reads markup, so a confirmed binary body can skip
	// the body work entirely — including BodyLowerString, whose lowered copy is a
	// second full-body allocation that nothing else would have asked for on an
	// image, font or PDF record.
	if class == modkit.ContentClassBinary {
		return out
	}

	// BodyLowerString is memoized on the response, so the body predicates below
	// share one lowercase copy rather than each making their own.
	lowerBody := resp.BodyLowerString()

	if class == modkit.ContentClassHTML && isRichHTML(lowerBody) {
		out |= SignalRichHTML
	}
	if dashboardsig.LooksLikeSPAShellLower(lowerBody) {
		out |= SignalSPA
	}
	if out&SignalUpload == 0 && hasFileInput(lowerBody) {
		out |= SignalUpload
	}

	return out
}

// hasClientInput reports whether the request carries anything an active module
// could inject into.
//
// Two families of position are deliberately not counted, both for the same
// reason — a signal that is true for nearly every record adds a constant and
// changes no ordering, which is the defect that makes a host-wide tech tag
// useless for ranking within a host:
//
//   - headers and cookies: every request has headers;
//   - path folder / path filename: an insertion-point analysis synthesizes these
//     from the path itself, so any URL with a segment has them. Counting them
//     made this signal fire on 100% of records in the module's own tests.
//
// What remains — a query string, or a body — is answerable from the request
// directly. It deliberately does NOT go through ScanContext.GetInsertionPoints:
// that cache keys shallow analyses separately from the nested ones every active
// module asks for, so this module would never hit a warm entry, would pay a full
// CreateAllInsertionPoints (including a raw-request clone) per record, and would
// insert 290k shallow entries that evict the nested ones the active fleet reuses.
func hasClientInput(req *httpmsg.HttpRequest) bool {
	if len(req.Body()) > 0 {
		return true
	}
	u, err := req.URL()
	return err == nil && u != nil && u.RawQuery != ""
}

// isStateChanging reports whether the method mutates server state. GET and HEAD
// do not; the executor already drops OPTIONS/TRACE/CONNECT upstream.
func isStateChanging(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// hasLegacyHandlerExtension reports whether the path names a server-executed
// handler of an older generation.
//
// Path() returns the request target from the request line, which INCLUDES any
// query string, so that is trimmed first — otherwise /x.php?next=/a.jsp would be
// judged on the query. The second check catches PATH_INFO routing
// (/index.php/users/1), which is itself a legacy shape worth the point.
func hasLegacyHandlerExtension(path string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	for i, ext := range legacyHandlerExtensions {
		if strings.HasSuffix(p, ext) || strings.Contains(p, legacyHandlerPathInfoPrefixes[i]) {
			return true
		}
	}
	return false
}

// isAuthBearing reports whether the exchange carries identity. Any of an
// Authorization header, a request Cookie, or a response Set-Cookie qualifies:
// each marks a record where the application is tracking who is asking, which is
// where access-control and IDOR surface lives.
func isAuthBearing(req *httpmsg.HttpRequest, resp *httpmsg.HttpResponse) bool {
	if req.Header("Authorization") != "" || req.Header("Cookie") != "" {
		return true
	}
	return resp != nil && resp.Header("Set-Cookie") != ""
}

// isMultipartRequest reports whether the request itself is a file upload. Split
// from hasFileInput so the request half can be decided before any body work.
func isMultipartRequest(req *httpmsg.HttpRequest) bool {
	ct := req.Header("Content-Type")
	return ct != "" && strings.Contains(strings.ToLower(ct), "multipart/form-data")
}

// hasFileInput reports whether the response offers a file upload. lowerBody must
// already be lowercased.
func hasFileInput(lowerBody string) bool {
	return strings.Contains(lowerBody, `type="file"`) ||
		strings.Contains(lowerBody, "type='file'") ||
		strings.Contains(lowerBody, "type=file")
}

// isRichHTML reports whether an HTML body carries interactive or navigational
// substance. lowerBody must already be lowercased.
//
// It deliberately does not use body size: an HTML document whose bulk is an
// inline JS bundle is large and thin at the same time, and crediting it would
// make the signal a proxy for page weight. Form inputs and links are what a
// scanner can actually act on.
func isRichHTML(lowerBody string) bool {
	if lowerBody == "" {
		return false
	}
	// Confirm it really is a document. A JSON or plain-text error page served as
	// text/html reaches here with class HTML and would otherwise be judged on
	// substring counts that mean nothing outside markup.
	if !strings.Contains(lowerBody, "<html") &&
		!strings.Contains(lowerBody, "<!doctype html") &&
		!strings.Contains(lowerBody, "<body") {
		return false
	}
	if strings.Contains(lowerBody, "<input") ||
		strings.Contains(lowerBody, "<textarea") ||
		strings.Contains(lowerBody, "<select") {
		return true
	}
	return strings.Count(lowerBody, "<a ") >= richHTMLMinAnchors
}

// isResponsive reports whether the application answered. An edge block or
// challenge is the CDN talking, not the app, and an error status is normally not
// surface worth prioritizing.
//
// The exception is an error that leaks a stack trace. A 500 dumping file paths
// and frame lines is the application talking, verbosely — the most interesting
// thing a target can do — so excluding it as "an error" would score the single
// most attackable response in a corpus the same as a blank 404. That case is
// folded in here rather than taking a signal of its own, because it is the same
// question ("did the app answer?") with a better answer.
//
// A 4xx without a trace stays neutral rather than penalized: the score floor is
// 0, so a protected 401/403 endpoint simply does not earn this signal while
// still earning the auth-bearing, JSON and tech-stack ones.
func isResponsive(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	if modkit.IsEdgeBlockedResponse(resp) {
		return false
	}
	if len(resp.Body()) == 0 {
		return false
	}
	if code := resp.StatusCode(); code >= 200 && code < 400 {
		return true
	}
	return modkit.BodyHasStackTrace(resp.BodyToString())
}
