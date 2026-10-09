package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Reasons a login check reports. Stable strings: `auth load -j` prints them and
// a caller branches on them.
const (
	// LoginReasonUnverified: the flow ran without error but there was no expect
	// block, and nothing in the response proved the login worked (or the login
	// form came back). A warning: the session is kept, the command exits 0.
	LoginReasonUnverified = "unverified"
	// LoginReasonExpectStatus: an expect.status block rejected the status.
	LoginReasonExpectStatus = "expect_status_mismatch"
	// LoginReasonExpectBody: an expect.body_contains block did not match.
	LoginReasonExpectBody = "expect_body_missing"
	// LoginReasonUnexpectedStatus: no expect block, and the status was outside
	// 2xx/3xx.
	LoginReasonUnexpectedStatus = "unexpected_status"
	// LoginReasonExtractFailed: an extract rule found nothing.
	LoginReasonExtractFailed = "extract_failed"
	// LoginReasonNetworkError: the request did not complete (connect, TLS,
	// timeout, cancellation, body read).
	LoginReasonNetworkError = "network_error"
	// LoginReasonInvalidFlow: the flow could not be built (no login, bad URL,
	// unparsable login_request).
	LoginReasonInvalidFlow = "invalid_flow"

	// Set by callers that report a session without checking it (OK, not
	// Verified): one with static headers and no login, and one skipped by
	// `auth load --no-validate`.
	LoginReasonStaticHeaders = "static_headers"
	LoginReasonNotValidated  = "not_validated"
)

// LoginResult is what CheckLogin observed for one session.
type LoginResult struct {
	Session string `json:"session"`
	// OK is false when the login failed: exit 1 for `auth load`. An OK result
	// with a Reason (unverified) is a warning.
	OK bool `json:"ok"`
	// Verified: an expect block passed, or the response showed the login
	// worked (a credential extracted, or a redirect away from the login URL)
	// with no login form left in it.
	Verified bool `json:"verified"`
	// Status is the status of the last response the flow received.
	Status int `json:"status,omitempty"`
	// URL is the request URL of the last request sent (the failing step's, for
	// a multi-step flow that stopped early).
	URL string `json:"url,omitempty"`
	// FinalURL is where that request ended up after redirects.
	FinalURL  string   `json:"final_url,omitempty"`
	Redirects []string `json:"redirects,omitempty"`
	// Step is the index of the last step attempted in a multi-step flow; absent
	// for a single-request flow.
	Step *int `json:"step,omitempty"`
	// ExtractedHeaders names (never values) the headers the login produced.
	ExtractedHeaders []string `json:"extracted_headers,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	// Message explains a failure or a warning in prose.
	Message string `json:"message,omitempty"`
	// Err is the failure, for Go callers.
	Err error `json:"-"`
}

// CheckLogin runs sess's login flow — single request or multi-step `steps`,
// with every `expect` block enforced — and reports what happened instead of a
// bare error. It hydrates sess on success, exactly as a scan's login does,
// because it IS a scan's login (executeLogin), not a separate probe.
//
// client supplies the transport (proxy, target TLS; see pkg/http.LoginTransport)
// and is copied, never mutated. A nil client uses Go's default transport.
//
// A session with only login_request is converted first, as NewManager does.
//
// With no expect block, success is unproven, so the response is judged: a
// password input still in the final body means the login form came back
// (unverified, with that said); a credential extracted or a redirect away from
// the login URL verifies it; anything else is unverified. Unverified is OK with
// a warning, never a failure: only an explicit expect, a status outside
// 2xx/3xx, a failed extract or a transport error fails.
func CheckLogin(ctx context.Context, sess *Session, client *http.Client) LoginResult {
	res := LoginResult{Session: sess.Name}
	if ctx == nil {
		ctx = context.Background()
	}
	if sess.Login == nil && sess.LoginRequest != "" {
		// Log in through a converted copy so sess keeps login_request as its
		// only login source (a stored row with both is ambiguous); the
		// credentials the login earned are copied back.
		conv := *sess
		if err := conv.convertLoginRequest(); err != nil {
			return res.fail(LoginReasonInvalidFlow, err)
		}
		res = CheckLogin(ctx, &conv, client)
		sess.Headers, sess.hydrated = conv.Headers, conv.hydrated
		return res
	}
	if sess.Login == nil {
		return res.fail(LoginReasonInvalidFlow, fmt.Errorf("session %q: no login flow defined", sess.Name))
	}

	tr := &loginTrace{step: -1}
	c := &http.Client{}
	if client != nil {
		*c = *client
	}
	prevRedirect := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		tr.redirects = append(tr.redirects, req.URL.String())
		if prevRedirect != nil {
			return prevRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}

	err := runLogin(ctx, sess, c, tr)
	res.Status = tr.status
	res.URL = tr.requestURL
	res.FinalURL = tr.finalURL
	res.Redirects = tr.redirects
	if tr.step >= 0 {
		step := tr.step
		res.Step = &step
	}
	res.ExtractedHeaders = headerNames(sess.Headers)
	if err != nil {
		reason := LoginReasonNetworkError
		var le *loginError
		if errors.As(err, &le) {
			reason = le.reason
		}
		return res.fail(reason, err)
	}

	res.OK = true
	if finalExpect(sess.Login) != nil {
		res.Verified = true
		return res
	}
	movedAway := tr.finalURL != "" && !sameURL(tr.finalURL, tr.requestURL)
	switch {
	case loginFormPresent(tr.body):
		res.Reason = LoginReasonUnverified
		res.Message = "the response still contains a password field, so the login form probably came back; add login.expect (status / body_contains) to make this a failure"
	case len(res.ExtractedHeaders) > 0 || movedAway:
		res.Verified = true
	default:
		res.Reason = LoginReasonUnverified
		res.Message = "no expect block, no credential extracted and no redirect away from the login URL; add login.expect to verify the login"
	}
	return res
}

func (r LoginResult) fail(reason string, err error) LoginResult {
	r.OK = false
	r.Verified = false
	r.Reason = reason
	r.Err = err
	r.Message = err.Error()
	return r
}

// finalExpect is the expect block that judges the flow's last response: the
// flow's own, or the last step's for a multi-step flow.
func finalExpect(lf *LoginFlow) *ExpectResponse {
	if len(lf.Steps) > 0 {
		return lf.Steps[len(lf.Steps)-1].Expect
	}
	return lf.Expect
}

// loginTrace records what a login flow saw. Every method is nil-safe, so the
// scan path (executeLogin) passes nil and pays nothing.
type loginTrace struct {
	step       int
	requestURL string
	status     int
	finalURL   string
	redirects  []string
	body       []byte
}

func (t *loginTrace) begin(step int, requestURL string) {
	if t == nil {
		return
	}
	t.step = step
	t.requestURL = requestURL
	t.status, t.finalURL, t.redirects, t.body = 0, "", nil, nil
}

func (t *loginTrace) observe(resp *http.Response, body []byte) {
	if t == nil {
		return
	}
	t.status = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		t.finalURL = resp.Request.URL.String()
	}
	t.body = body
}

// loginError carries a LoginReason through the error chain; its message is the
// wrapped error's, so callers that only print see what they always saw.
type loginError struct {
	reason string
	err    error
}

func (e *loginError) Error() string { return e.err.Error() }
func (e *loginError) Unwrap() error { return e.err }

func loginFailf(reason, format string, args ...any) error {
	return &loginError{reason: reason, err: fmt.Errorf(format, args...)}
}

// checkExpect is ValidateExpect with the failing constraint named.
func checkExpect(expect *ExpectResponse, statusCode int, body []byte) (string, error) {
	if expect == nil {
		return "", nil
	}
	if len(expect.Status) > 0 {
		found := false
		for _, s := range expect.Status {
			if s == statusCode {
				found = true
				break
			}
		}
		if !found {
			return LoginReasonExpectStatus, fmt.Errorf("unexpected status %d (expected one of %v)", statusCode, expect.Status)
		}
	}
	if expect.BodyContains != "" && !strings.Contains(string(body), expect.BodyContains) {
		return LoginReasonExpectBody, fmt.Errorf("response body does not contain %q", expect.BodyContains)
	}
	return "", nil
}

var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]*\btype\s*=\s*["']?password\b`)

// loginFormPresent reports whether body still carries a password input.
func loginFormPresent(body []byte) bool {
	return passwordInputRe.Match(body)
}

// sameURL compares two URLs ignoring a trailing slash and the fragment.
func sameURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return a == b
	}
	norm := func(u *url.URL) string {
		u.Fragment = ""
		u.Path = strings.TrimSuffix(u.Path, "/")
		u.Host = strings.ToLower(u.Host)
		return u.String()
	}
	return norm(ua) == norm(ub)
}

func headerNames(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
