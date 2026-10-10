package authentication

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/utils/yamlschema"
	"gopkg.in/yaml.v3"
)

// loggedin.go is the ONE answer to "is this session logged in?". The session
// file's `check` block configures it, AssessAuthenticated applies it to an
// authenticated response and its anonymous baseline (`vigolium auth check`),
// and CheckMatcher exposes the same rules one response at a time for the
// in-scan session watcher (sampling scan traffic, the active probe before a
// re-login). The `reauth` block says what that watcher does once a session is
// confirmed logged out.

// Duration is a session-file duration: "90s", "2m", "1h30m". A bare integer is
// seconds. Zero means unset.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func parseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return Duration(time.Duration(n) * time.Second), nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (want e.g. \"30s\", \"2m\")", s)
	}
	return Duration(v), nil
}

// UnmarshalYAML accepts "2m" or a bare number of seconds.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string such as \"2m\"", n.Line)
	}
	v, err := parseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = v
	return nil
}

// MarshalYAML writes the duration in Go's notation ("2m0s").
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// UnmarshalJSON accepts "2m" or a number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n float64
		if numErr := json.Unmarshal(b, &n); numErr != nil {
			return errors.New("duration must be a string such as \"2m\" or a number of seconds")
		}
		*d = Duration(time.Duration(n * float64(time.Second)))
		return nil
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalJSON writes the duration in Go's notation ("2m0s").
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// LoggedInRule holds on a response that proves the session is logged in. ALL
// configured conditions must hold.
type LoggedInRule struct {
	Status       []int  `yaml:"status,omitempty" json:"status,omitempty"`
	BodyContains string `yaml:"body_contains,omitempty" json:"body_contains,omitempty"`
	BodyRegex    string `yaml:"body_regex,omitempty" json:"body_regex,omitempty"`
	// HeaderRegex is matched against each response header rendered as
	// "Name: value" (e.g. 'Content-Type: application/json').
	HeaderRegex string `yaml:"header_regex,omitempty" json:"header_regex,omitempty"`
}

func (r *LoggedInRule) empty() bool {
	return r == nil || (len(r.Status) == 0 && r.BodyContains == "" && r.BodyRegex == "" && r.HeaderRegex == "")
}

// LoggedOutRule marks a response as a sign the session is gone. ANY matching
// condition counts.
type LoggedOutRule struct {
	Status []int `yaml:"status,omitempty" json:"status,omitempty"`
	// RedirectRegex is matched against the Location header of a 3xx.
	RedirectRegex string `yaml:"redirect_regex,omitempty" json:"redirect_regex,omitempty"`
	BodyRegex     string `yaml:"body_regex,omitempty" json:"body_regex,omitempty"`
}

func (r *LoggedOutRule) empty() bool {
	return r == nil || (len(r.Status) == 0 && r.RedirectRegex == "" && r.BodyRegex == "")
}

// hasCheapIndicator: a status or redirect rule, which the scan can evaluate on
// every response without an active probe.
func (r *LoggedOutRule) hasCheapIndicator() bool {
	return r != nil && (len(r.Status) > 0 || r.RedirectRegex != "")
}

// Defaults for the check and reauth blocks.
const (
	DefaultCheckMethod       = http.MethodGet
	DefaultCheckSampleEvery  = 50
	DefaultReauthMaxAttempts = 3
	DefaultReauthBackoff     = 10 * time.Second
)

// SessionCheck is a session's `check` block: how to tell whether it is still
// logged in.
type SessionCheck struct {
	// URL is the active probe. A path ("/api/me") resolves against the target
	// origin. Optional when logged_out has a status or redirect indicator.
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	// LoggedIn must hold on the probe's response.
	LoggedIn *LoggedInRule `yaml:"logged_in,omitempty" json:"logged_in,omitempty"`
	// LoggedOut flags scan traffic (and the probe) as logged out.
	LoggedOut *LoggedOutRule `yaml:"logged_out,omitempty" json:"logged_out,omitempty"`
	// SampleEvery evaluates the logged_out body regex on 1 in N scan
	// responses (status and Location are checked on every response). 0 means
	// DefaultCheckSampleEvery.
	SampleEvery int `yaml:"sample_every,omitempty" json:"sample_every,omitempty"`
	// Interval runs the active probe proactively at most this often; 0 probes
	// only when traffic looks logged out.
	Interval Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
}

// EffectiveMethod is Method or GET.
func (c *SessionCheck) EffectiveMethod() string {
	if c == nil || strings.TrimSpace(c.Method) == "" {
		return DefaultCheckMethod
	}
	return strings.ToUpper(strings.TrimSpace(c.Method))
}

// EffectiveSampleEvery is SampleEvery or DefaultCheckSampleEvery.
func (c *SessionCheck) EffectiveSampleEvery() int {
	if c == nil || c.SampleEvery <= 0 {
		return DefaultCheckSampleEvery
	}
	return c.SampleEvery
}

// ReauthOnFailure is what a scan does when re-login keeps failing.
type ReauthOnFailure string

const (
	// ReauthContinue keeps scanning unauthenticated; the phase is partial with
	// reason auth_lost. The default (decision D19).
	ReauthContinue ReauthOnFailure = "continue"
	// ReauthAbort cancels the scan with a typed error.
	ReauthAbort ReauthOnFailure = "abort"
)

// SessionReauth is a session's `reauth` block: what to do once the check
// confirms it is logged out.
type SessionReauth struct {
	// Enabled defaults to true when the session has a check block.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// MaxAttempts is the number of consecutive failed re-logins before giving
	// up. 0 means DefaultReauthMaxAttempts.
	MaxAttempts int `yaml:"max_attempts,omitempty" json:"max_attempts,omitempty"`
	// Backoff is the wait after the first failure; it doubles per failure.
	// 0 means DefaultReauthBackoff.
	Backoff   Duration        `yaml:"backoff,omitempty" json:"backoff,omitempty"`
	OnFailure ReauthOnFailure `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`
	// PauseTraffic holds this session's requests while it re-logs in. Default
	// true.
	PauseTraffic *bool `yaml:"pause_traffic,omitempty" json:"pause_traffic,omitempty"`
}

// ReauthEnabled reports whether a scan should re-login s when its check says
// it is logged out, or ahead of its credentials' known expiry: it needs a
// check to notice (or an expiry to refresh ahead of) and a login flow to
// re-run, and `reauth.enabled: false` turns it off.
func (s *Session) ReauthEnabled() bool {
	if (s.Check == nil && s.expiresAt.IsZero()) || (s.Login == nil && s.LoginRequest == "") {
		return false
	}
	if s.Reauth != nil && s.Reauth.Enabled != nil {
		return *s.Reauth.Enabled
	}
	return true
}

// EffectiveMaxAttempts is MaxAttempts or DefaultReauthMaxAttempts.
func (r *SessionReauth) EffectiveMaxAttempts() int {
	if r == nil || r.MaxAttempts <= 0 {
		return DefaultReauthMaxAttempts
	}
	return r.MaxAttempts
}

// EffectiveBackoff is Backoff or DefaultReauthBackoff.
func (r *SessionReauth) EffectiveBackoff() time.Duration {
	if r == nil || r.Backoff <= 0 {
		return DefaultReauthBackoff
	}
	return r.Backoff.D()
}

// EffectiveOnFailure is OnFailure or ReauthContinue.
func (r *SessionReauth) EffectiveOnFailure() ReauthOnFailure {
	if r == nil || r.OnFailure == "" {
		return ReauthContinue
	}
	return r.OnFailure
}

// EffectivePauseTraffic is PauseTraffic or true.
func (r *SessionReauth) EffectivePauseTraffic() bool {
	if r == nil || r.PauseTraffic == nil {
		return true
	}
	return *r.PauseTraffic
}

// SessionDefaults are the config-wide values (scanning_strategy.session) that
// fill in what a session's own check block leaves unset.
type SessionDefaults struct {
	// ValidateURL fills check.url.
	ValidateURL string
	// ReauthOnStatus fills check.logged_out.status.
	ReauthOnStatus []int
	// ReauthInterval fills check.interval.
	ReauthInterval time.Duration
}

func (d SessionDefaults) empty() bool {
	return d.ValidateURL == "" && len(d.ReauthOnStatus) == 0 && d.ReauthInterval <= 0
}

// ApplyDefaults fills s's check block from d: a value the session sets always
// wins. A session with no check block gets one when d has anything to say.
// The session's own block is copied, never mutated in place, so a Session
// shared between callers is not changed behind their back.
func (s *Session) ApplyDefaults(d SessionDefaults) {
	if d.empty() {
		return
	}
	c := &SessionCheck{}
	if s.Check != nil {
		cp := *s.Check
		c = &cp
	}
	if c.URL == "" {
		c.URL = d.ValidateURL
	}
	if len(d.ReauthOnStatus) > 0 && (c.LoggedOut == nil || len(c.LoggedOut.Status) == 0) {
		lo := LoggedOutRule{}
		if c.LoggedOut != nil {
			lo = *c.LoggedOut
		}
		lo.Status = slices.Clone(d.ReauthOnStatus)
		c.LoggedOut = &lo
	}
	if c.Interval == 0 && d.ReauthInterval > 0 {
		c.Interval = Duration(d.ReauthInterval)
	}
	s.Check = c
}

// ResolveCheckURL resolves the check URL against base: an absolute URL is
// returned as is, a path is joined to base's origin. base may be any URL on
// the target (the login URL, a scan target).
func ResolveCheckURL(checkURL, base string) (string, error) {
	checkURL = strings.TrimSpace(checkURL)
	if checkURL == "" {
		return "", errors.New("no check URL")
	}
	u, err := url.Parse(checkURL)
	if err != nil {
		return "", fmt.Errorf("invalid check URL %q: %w", checkURL, err)
	}
	if u.IsAbs() {
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", fmt.Errorf("check URL scheme must be http or https, got %q", u.Scheme)
		}
		return u.String(), nil
	}
	if base == "" {
		return "", fmt.Errorf("check URL %q is relative and there is no target to resolve it against", checkURL)
	}
	b, err := url.Parse(base)
	if err != nil || !b.IsAbs() || b.Host == "" {
		return "", fmt.Errorf("cannot resolve relative check URL %q against %q", checkURL, base)
	}
	origin := &url.URL{Scheme: b.Scheme, Host: b.Host, Path: "/"}
	return origin.ResolveReference(u).String(), nil
}

// ---------------------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------------------

// ProbeResponse is one response the logged-in rules judge. Err set means the
// request did not complete.
type ProbeResponse struct {
	Status int
	Header http.Header
	Body   []byte
	// URL is the request URL, used to resolve a relative Location.
	URL string
	Err error
}

// Location is the response's Location header, resolved against URL.
func (p *ProbeResponse) Location() string {
	if p == nil || p.Header == nil {
		return ""
	}
	loc := strings.TrimSpace(p.Header.Get("Location"))
	if loc == "" || p.URL == "" {
		return loc
	}
	base, err := url.Parse(p.URL)
	if err != nil {
		return loc
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return base.ResolveReference(ref).String()
}

func (p *ProbeResponse) ok() bool { return p != nil && p.Err == nil }

func isRedirect(status int) bool { return status >= 300 && status < 400 }

// CheckMatcher is a compiled check block. A nil *CheckMatcher matches nothing
// (no rules configured).
type CheckMatcher struct {
	check *SessionCheck

	inBody, inHeader *regexp.Regexp
	outRedirect      *regexp.Regexp
	outBody          *regexp.Regexp
}

// Compile compiles the check's regexes. A nil check compiles to nil.
func (c *SessionCheck) Compile() (*CheckMatcher, error) {
	if c == nil {
		return nil, nil
	}
	m := &CheckMatcher{check: c}
	var err error
	compile := func(field, expr string) *regexp.Regexp {
		if expr == "" || err != nil {
			return nil
		}
		re, cerr := regexp.Compile(expr)
		if cerr != nil {
			err = fmt.Errorf("check.%s: %w", field, cerr)
		}
		return re
	}
	if c.LoggedIn != nil {
		m.inBody = compile("logged_in.body_regex", c.LoggedIn.BodyRegex)
		m.inHeader = compile("logged_in.header_regex", c.LoggedIn.HeaderRegex)
	}
	if c.LoggedOut != nil {
		m.outRedirect = compile("logged_out.redirect_regex", c.LoggedOut.RedirectRegex)
		m.outBody = compile("logged_out.body_regex", c.LoggedOut.BodyRegex)
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// HasLoggedIn reports whether a logged_in rule is configured.
func (m *CheckMatcher) HasLoggedIn() bool { return m != nil && !m.check.LoggedIn.empty() }

// HasLoggedOut reports whether a logged_out rule is configured.
func (m *CheckMatcher) HasLoggedOut() bool { return m != nil && !m.check.LoggedOut.empty() }

// LoggedIn reports whether every configured logged_in condition holds on p,
// and names the first that failed. False when no rule is configured.
func (m *CheckMatcher) LoggedIn(p *ProbeResponse) (bool, string) {
	if !m.HasLoggedIn() || !p.ok() {
		return false, ""
	}
	r := m.check.LoggedIn
	if len(r.Status) > 0 && !slices.Contains(r.Status, p.Status) {
		return false, fmt.Sprintf("status %d not in logged_in.status %v", p.Status, r.Status)
	}
	if r.BodyContains != "" && !strings.Contains(string(p.Body), r.BodyContains) {
		return false, fmt.Sprintf("body does not contain logged_in.body_contains %q", r.BodyContains)
	}
	if m.inBody != nil && !m.inBody.Match(p.Body) {
		return false, "body does not match logged_in.body_regex"
	}
	if m.inHeader != nil && !headerMatches(m.inHeader, p.Header) {
		return false, "no header matches logged_in.header_regex"
	}
	return true, ""
}

// LoggedOut reports whether any logged_out condition matches p, and which
// ("status", "redirect" or "body"). checkBody=false skips the body regex: the
// scan's sampler evaluates status and Location on every response and the body
// only on 1 in sample_every.
func (m *CheckMatcher) LoggedOut(p *ProbeResponse, checkBody bool) (bool, string) {
	if !m.HasLoggedOut() || !p.ok() {
		return false, ""
	}
	r := m.check.LoggedOut
	if slices.Contains(r.Status, p.Status) {
		return true, "status"
	}
	if m.outRedirect != nil && isRedirect(p.Status) && m.outRedirect.MatchString(p.Location()) {
		return true, "redirect"
	}
	if checkBody && m.outBody != nil && m.outBody.Match(p.Body) {
		return true, "body"
	}
	return false, ""
}

func headerMatches(re *regexp.Regexp, h http.Header) bool {
	for name, vals := range h {
		for _, v := range vals {
			if re.MatchString(name + ": " + v) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AssessAuthenticated
// ---------------------------------------------------------------------------

// Verdict is what AssessAuthenticated concluded about a session on one URL.
type Verdict string

const (
	// VerdictAuthenticated: the session reached content the anonymous baseline
	// did not (or the configured logged_in rule held and the baseline failed
	// it).
	VerdictAuthenticated Verdict = "authenticated"
	// VerdictLoginWall: the authenticated request was sent to a login page
	// (a redirect to a login URL, or a password form in the body).
	VerdictLoginWall Verdict = "login_wall"
	// VerdictUnauthorized: the server refused the credentials (401/403, a
	// configured logged_out status, or a failed logged_in rule).
	VerdictUnauthorized Verdict = "unauthorized"
	// VerdictIndistinguishable: the authenticated and anonymous responses are
	// the same, so the URL proves nothing (a public page, or credentials the
	// server ignores). Pick a protected URL or configure check.logged_in.
	VerdictIndistinguishable Verdict = "indistinguishable"
	// VerdictError: a request failed or the check block is invalid.
	VerdictError Verdict = "error"
)

// Signal is one piece of evidence AssessAuthenticated used. Side is "auth" or
// "anon" when the signal is about one response, empty for a comparison.
type Signal struct {
	Name   string `json:"name"`
	Side   string `json:"side,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Signal names.
const (
	SignalStatusPair         = "status_pair"
	SignalLoginRedirect      = "login_redirect"
	SignalPasswordInput      = "password_input"
	SignalBodySimilarity     = "body_similarity"
	SignalConfiguredLoggedIn = "configured_logged_in"
	SignalConfiguredLogOut   = "configured_logged_out"
	SignalRequestFailed      = "request_failed"
	SignalInvalidCheck       = "invalid_check"
)

// Assessment is AssessAuthenticated's result.
type Assessment struct {
	Verdict Verdict  `json:"verdict"`
	Reason  string   `json:"reason"`
	Signals []Signal `json:"signals,omitempty"`
	// Similarity is the auth/anon body similarity in [0,1], or -1 when it was
	// not computed.
	Similarity float64 `json:"similarity"`
}

// Authenticated is Verdict == VerdictAuthenticated.
func (a Assessment) Authenticated() bool { return a.Verdict == VerdictAuthenticated }

// indistinguishableSimilarity: bodies at least this similar (after volatile
// tokens are masked) with the same status are "the same page".
const indistinguishableSimilarity = 0.995

// loginPathRe recognises a Location that points at a login page.
var loginPathRe = regexp.MustCompile(`(?i)(/(login|log-in|log_in|logon|signin|sign-in|sign_in|auth|authenticate|sso|cas|oauth2?|session/new|users/sign_in|account/login)\b|[?&](returnurl|return_to|returnto|redirect_uri|continue)=)`)

// AssessAuthenticated decides whether authResp (the URL fetched with the
// session's credentials) shows a logged-in session, using anonResp (the same
// request without them) as the baseline. check is the session's check block
// (nil for none): a configured logged_out match is decisive, a configured
// logged_in rule overrides the heuristics, and the heuristics are the status
// pair, a redirect to a login URL, a password input, and body similarity.
func AssessAuthenticated(authResp, anonResp *ProbeResponse, check *SessionCheck) Assessment {
	a := Assessment{Similarity: -1}
	add := func(name, side, format string, args ...any) {
		a.Signals = append(a.Signals, Signal{Name: name, Side: side, Detail: fmt.Sprintf(format, args...)})
	}
	done := func(v Verdict, format string, args ...any) Assessment {
		a.Verdict = v
		a.Reason = fmt.Sprintf(format, args...)
		return a
	}

	m, err := check.Compile()
	if err != nil {
		add(SignalInvalidCheck, "", "%v", err)
		return done(VerdictError, "invalid check block: %v", err)
	}
	if authResp == nil || authResp.Err != nil {
		e := errors.New("no response")
		if authResp != nil {
			e = authResp.Err
		}
		add(SignalRequestFailed, "auth", "%v", e)
		return done(VerdictError, "authenticated request failed: %v", e)
	}
	if anonResp == nil || anonResp.Err != nil {
		e := errors.New("no response")
		if anonResp != nil {
			e = anonResp.Err
		}
		add(SignalRequestFailed, "anon", "%v", e)
		return done(VerdictError, "anonymous baseline request failed: %v", e)
	}
	add(SignalStatusPair, "", "auth=%d anon=%d", authResp.Status, anonResp.Status)

	// 1. A configured logged_out match on the authenticated response is
	// decisive: the operator said what "logged out" looks like.
	if out, how := m.LoggedOut(authResp, true); out {
		add(SignalConfiguredLogOut, "auth", "matched logged_out.%s", how)
		if how == "redirect" || (how == "body" && !isDenied(authResp.Status)) {
			return done(VerdictLoginWall, "authenticated response matches check.logged_out (%s)", how)
		}
		return done(VerdictUnauthorized, "authenticated response matches check.logged_out (%s, status %d)", how, authResp.Status)
	}

	authLogin := loginSignal(authResp)
	anonLogin := loginSignal(anonResp)

	// 2. A configured logged_in rule decides, unless the anonymous baseline
	// passes it too (then the rule proves nothing on this URL).
	if m.HasLoggedIn() {
		in, why := m.LoggedIn(authResp)
		if !in {
			add(SignalConfiguredLoggedIn, "auth", "failed: %s", why)
			switch {
			case authLogin != "":
				add(authLogin, "auth", "%s", loginDetail(authResp, authLogin))
				return done(VerdictLoginWall, "check.logged_in failed (%s) and the response is a login page", why)
			default:
				return done(VerdictUnauthorized, "check.logged_in failed: %s", why)
			}
		}
		add(SignalConfiguredLoggedIn, "auth", "held")
		if anonIn, _ := m.LoggedIn(anonResp); anonIn {
			add(SignalConfiguredLoggedIn, "anon", "held")
			return done(VerdictIndistinguishable, "check.logged_in also holds without credentials, so it does not prove a login on this URL")
		}
		add(SignalConfiguredLoggedIn, "anon", "failed")
		return done(VerdictAuthenticated, "check.logged_in holds with credentials and fails without them")
	}

	// 3. Heuristics on the authenticated side.
	if isDenied(authResp.Status) {
		return done(VerdictUnauthorized, "authenticated request got status %d", authResp.Status)
	}
	if authLogin != "" {
		add(authLogin, "auth", "%s", loginDetail(authResp, authLogin))
		return done(VerdictLoginWall, "authenticated request was sent to a login page (%s)", loginDetail(authResp, authLogin))
	}

	// 4. The anonymous baseline was turned away where the session was not.
	if out, how := m.LoggedOut(anonResp, true); out {
		add(SignalConfiguredLogOut, "anon", "matched logged_out.%s", how)
		return done(VerdictAuthenticated, "the anonymous baseline matches check.logged_out (%s); the session does not", how)
	}
	if isDenied(anonResp.Status) {
		return done(VerdictAuthenticated, "status %d with credentials, %d without", authResp.Status, anonResp.Status)
	}
	if anonLogin != "" {
		add(anonLogin, "anon", "%s", loginDetail(anonResp, anonLogin))
		return done(VerdictAuthenticated, "the anonymous baseline gets a login page (%s); the session does not", loginDetail(anonResp, anonLogin))
	}

	// 5. Neither side was refused: compare them.
	if authResp.Status != anonResp.Status {
		return done(VerdictAuthenticated, "status %d with credentials, %d without", authResp.Status, anonResp.Status)
	}
	if isRedirect(authResp.Status) && authResp.Location() != anonResp.Location() {
		return done(VerdictAuthenticated, "redirect to %s with credentials, %s without", authResp.Location(), anonResp.Location())
	}
	a.Similarity = BodySimilarity(authResp.Body, anonResp.Body)
	add(SignalBodySimilarity, "", "%.3f", a.Similarity)
	if a.Similarity >= indistinguishableSimilarity {
		return done(VerdictIndistinguishable, "the response is the same with and without credentials (status %d, body similarity %.3f); use a URL only a logged-in user can see, or configure check.logged_in", authResp.Status, a.Similarity)
	}
	return done(VerdictAuthenticated, "the response differs with credentials (status %d, body similarity %.3f)", authResp.Status, a.Similarity)
}

func isDenied(status int) bool { return status == 401 || status == 403 || status == 407 }

// loginSignal names the login-page sign p carries: a redirect to a login URL,
// or a password input. "" for none.
func loginSignal(p *ProbeResponse) string {
	if isRedirect(p.Status) && loginPathRe.MatchString(p.Location()) {
		return SignalLoginRedirect
	}
	if loginFormPresent(p.Body) {
		return SignalPasswordInput
	}
	return ""
}

func loginDetail(p *ProbeResponse, signal string) string {
	if signal == SignalLoginRedirect {
		return fmt.Sprintf("%d to %s", p.Status, p.Location())
	}
	return "password input in the body"
}

// ---------------------------------------------------------------------------
// Body similarity
// ---------------------------------------------------------------------------

var (
	tokenRe  = regexp.MustCompile(`[\p{L}\p{N}_-]+`)
	digitsRe = regexp.MustCompile(`^[0-9_-]+$`)
)

// normalizeToken masks volatile tokens, which differ on every request: numbers,
// and long tokens mixing letters and digits (CSRF tokens, nonces, session IDs,
// hashes).
func normalizeToken(t string) string {
	if digitsRe.MatchString(t) {
		return "#"
	}
	if len(t) >= 12 && strings.ContainsAny(t, "0123456789") {
		return "#"
	}
	return strings.ToLower(t)
}

// BodySimilarity is the Dice coefficient of the two bodies' token multisets,
// with volatile tokens (numbers, nonces, IDs) masked: 1 means the same words
// in the same quantities, 0 nothing shared. Two empty bodies are identical.
func BodySimilarity(a, b []byte) float64 {
	ta := tokenRe.FindAll(a, -1)
	tb := tokenRe.FindAll(b, -1)
	if len(ta) == 0 && len(tb) == 0 {
		return 1
	}
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	counts := make(map[string]int, len(ta))
	for _, t := range ta {
		counts[normalizeToken(string(t))]++
	}
	shared := 0
	for _, t := range tb {
		k := normalizeToken(string(t))
		if counts[k] > 0 {
			counts[k]--
			shared++
		}
	}
	return 2 * float64(shared) / float64(len(ta)+len(tb))
}

// ---------------------------------------------------------------------------
// Validation (Session.Validate and auth lint share these rules)
// ---------------------------------------------------------------------------

var httpMethodRe = regexp.MustCompile(`^[A-Za-z]+$`)

// lintCheck validates a check block. prefix is its field path ("check" or
// "sessions[0].check").
func lintCheck(c *SessionCheck, prefix string) []LintIssue {
	if c == nil {
		return nil
	}
	var issues []LintIssue
	errorf := func(field, format string, args ...any) {
		issues = append(issues, LintIssue{Field: yamlschema.JoinPath(prefix, field), Severity: "error", Message: fmt.Sprintf(format, args...)})
	}
	warnf := func(field, format string, args ...any) {
		issues = append(issues, LintIssue{Field: yamlschema.JoinPath(prefix, field), Severity: "warning", Message: fmt.Sprintf(format, args...)})
	}

	if c.URL != "" {
		u, err := url.Parse(c.URL)
		switch {
		case err != nil:
			errorf("url", "invalid URL: %v", err)
		case u.IsAbs() && u.Scheme != "http" && u.Scheme != "https":
			errorf("url", "URL scheme must be http or https, got %q", u.Scheme)
		case u.IsAbs() && u.Host == "":
			errorf("url", "URL %q has no host", c.URL)
		case !u.IsAbs() && !strings.HasPrefix(c.URL, "/"):
			errorf("url", "must be an absolute http(s) URL or a path starting with \"/\" (resolved against the target origin), got %q", c.URL)
		}
	} else if !c.LoggedOut.hasCheapIndicator() {
		errorf("url", "required unless logged_out has a status or redirect_regex (scanning_strategy.session.validate_url and reauth_on_status supply these at scan time)")
	}
	if c.Method != "" && !httpMethodRe.MatchString(strings.TrimSpace(c.Method)) {
		errorf("method", "invalid HTTP method %q", c.Method)
	}

	if c.LoggedIn != nil {
		if c.LoggedIn.empty() {
			warnf("logged_in", "logged_in block is empty (no status, body_contains, body_regex or header_regex)")
		}
		issues = append(issues, lintStatuses(c.LoggedIn.Status, yamlschema.JoinPath(prefix, "logged_in.status"))...)
		issues = append(issues, lintRegex(c.LoggedIn.BodyRegex, yamlschema.JoinPath(prefix, "logged_in.body_regex"))...)
		issues = append(issues, lintRegex(c.LoggedIn.HeaderRegex, yamlschema.JoinPath(prefix, "logged_in.header_regex"))...)
		if c.URL == "" && !c.LoggedIn.empty() {
			warnf("logged_in", "logged_in is evaluated on the check.url probe, and there is no check.url")
		}
	}
	if c.LoggedOut != nil {
		if c.LoggedOut.empty() {
			warnf("logged_out", "logged_out block is empty (no status, redirect_regex or body_regex)")
		}
		issues = append(issues, lintStatuses(c.LoggedOut.Status, yamlschema.JoinPath(prefix, "logged_out.status"))...)
		issues = append(issues, lintRegex(c.LoggedOut.RedirectRegex, yamlschema.JoinPath(prefix, "logged_out.redirect_regex"))...)
		issues = append(issues, lintRegex(c.LoggedOut.BodyRegex, yamlschema.JoinPath(prefix, "logged_out.body_regex"))...)
	}
	if c.SampleEvery < 0 {
		errorf("sample_every", "sample_every must be >= 1 (omit it for the default %d), got %d", DefaultCheckSampleEvery, c.SampleEvery)
	}
	if c.Interval < 0 {
		errorf("interval", "interval must not be negative, got %s", c.Interval)
	}
	return issues
}

// lintReauth validates s's reauth block. prefix is its field path.
func lintReauth(s *Session, prefix string) []LintIssue {
	r := s.Reauth
	if r == nil {
		return nil
	}
	var issues []LintIssue
	errorf := func(field, format string, args ...any) {
		issues = append(issues, LintIssue{Field: yamlschema.JoinPath(prefix, field), Severity: "error", Message: fmt.Sprintf(format, args...)})
	}
	if r.MaxAttempts < 0 {
		errorf("max_attempts", "max_attempts must be >= 1 (omit it for the default %d), got %d", DefaultReauthMaxAttempts, r.MaxAttempts)
	}
	if r.Backoff < 0 {
		errorf("backoff", "backoff must not be negative, got %s", r.Backoff)
	}
	switch r.OnFailure {
	case "", ReauthContinue, ReauthAbort:
	default:
		errorf("on_failure", "invalid on_failure %q (must be \"continue\" or \"abort\")", r.OnFailure)
	}
	enabled := r.Enabled == nil || *r.Enabled
	if enabled && s.Check == nil && (s.Login == nil || !s.Login.Type.IsOAuth2()) {
		issues = append(issues, LintIssue{Field: prefix, Severity: "warning",
			Message: "reauth has no effect without a check block (or scanning_strategy.session defaults) to detect a logged-out session"})
	}
	if enabled && s.Login == nil && s.LoginRequest == "" {
		issues = append(issues, LintIssue{Field: prefix, Severity: "warning",
			Message: "reauth needs a login or login_request to re-run; static headers cannot be refreshed"})
	}
	return issues
}

func lintStatuses(codes []int, field string) []LintIssue {
	var issues []LintIssue
	for i, code := range codes {
		if code < 100 || code > 599 {
			issues = append(issues, LintIssue{Field: fmt.Sprintf("%s[%d]", field, i), Severity: "error",
				Message: fmt.Sprintf("invalid HTTP status code %d", code)})
		}
	}
	return issues
}

func lintRegex(expr, field string) []LintIssue {
	if expr == "" {
		return nil
	}
	if _, err := regexp.Compile(expr); err != nil {
		return []LintIssue{{Field: field, Severity: "error", Message: fmt.Sprintf("invalid regex: %v", err)}}
	}
	return nil
}
