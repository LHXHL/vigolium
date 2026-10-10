package authentication

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func probe(status int, body string, hdr ...string) *ProbeResponse {
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Add(hdr[i], hdr[i+1])
	}
	return &ProbeResponse{Status: status, Header: h, Body: []byte(body), URL: "https://app.test/account"}
}

const dashboard = `<html><body><h1>Account</h1><p>Signed in as alice@example.com</p><a href="/logout">Log out</a></body></html>`
const loginPage = `<html><body><form action="/login"><input name="user"><input type="password" name="pw"></form></body></html>`
const publicPage = `<html><body><h1>About us</h1><p>We make widgets.</p></body></html>`

func signalNames(a Assessment) []string {
	var out []string
	for _, s := range a.Signals {
		out = append(out, s.Name+":"+s.Side)
	}
	return out
}

func TestAssessAuthenticated_Heuristics(t *testing.T) {
	tests := []struct {
		name       string
		auth, anon *ProbeResponse
		want       Verdict
		signal     string
	}{
		{
			name: "anon redirected to login, auth sees the page",
			auth: probe(200, dashboard),
			anon: probe(302, "", "Location", "/login?next=/account"),
			want: VerdictAuthenticated, signal: SignalLoginRedirect + ":anon",
		},
		{
			name: "both redirected to login: login wall",
			auth: probe(302, "", "Location", "https://app.test/users/sign_in"),
			anon: probe(302, "", "Location", "https://app.test/users/sign_in"),
			want: VerdictLoginWall, signal: SignalLoginRedirect + ":auth",
		},
		{
			name: "login form served in place",
			auth: probe(200, loginPage),
			anon: probe(200, loginPage),
			want: VerdictLoginWall, signal: SignalPasswordInput + ":auth",
		},
		{
			name: "anon gets the form in place, auth the page",
			auth: probe(200, dashboard),
			anon: probe(200, loginPage),
			want: VerdictAuthenticated, signal: SignalPasswordInput + ":anon",
		},
		{
			name: "credentials refused",
			auth: probe(401, `{"error":"invalid token"}`),
			anon: probe(401, `{"error":"missing token"}`),
			want: VerdictUnauthorized,
		},
		{
			name: "403 with credentials",
			auth: probe(403, "forbidden"),
			anon: probe(200, publicPage),
			want: VerdictUnauthorized,
		},
		{
			name: "API 401 anon, 200 auth",
			auth: probe(200, `{"email":"alice@example.com"}`),
			anon: probe(401, `{"error":"unauthorized"}`),
			want: VerdictAuthenticated, signal: SignalStatusPair + ":",
		},
		{
			name: "public page: identical",
			auth: probe(200, publicPage),
			anon: probe(200, publicPage),
			want: VerdictIndistinguishable, signal: SignalBodySimilarity + ":",
		},
		{
			name: "identical apart from a CSRF nonce and a timestamp",
			auth: probe(200, publicPage+`<input name="csrf" value="a8f3b9c2d1e4f5a6b7c8"><span>1712345678</span>`),
			anon: probe(200, publicPage+`<input name="csrf" value="ffe1d2c3b4a5968778695a"><span>1712345690</span>`),
			want: VerdictIndistinguishable,
		},
		{
			name: "same status, different content",
			auth: probe(200, dashboard),
			anon: probe(200, publicPage),
			want: VerdictAuthenticated, signal: SignalBodySimilarity + ":",
		},
		{
			name: "auth request failed",
			auth: &ProbeResponse{Err: errors.New("connection refused")},
			anon: probe(200, publicPage),
			want: VerdictError, signal: SignalRequestFailed + ":auth",
		},
		{
			name: "anon request failed",
			auth: probe(200, dashboard),
			anon: &ProbeResponse{Err: errors.New("timeout")},
			want: VerdictError, signal: SignalRequestFailed + ":anon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AssessAuthenticated(tt.auth, tt.anon, nil)
			assert.Equal(t, tt.want, a.Verdict, a.Reason)
			assert.NotEmpty(t, a.Reason)
			if tt.signal != "" {
				assert.Contains(t, signalNames(a), tt.signal)
			}
		})
	}
}

func TestAssessAuthenticated_ConfiguredCheck(t *testing.T) {
	check := &SessionCheck{
		URL:      "/api/me",
		LoggedIn: &LoggedInRule{Status: []int{200}, BodyContains: `"email"`, HeaderRegex: `(?i)^content-type: application/json`},
		LoggedOut: &LoggedOutRule{
			Status:        []int{419},
			RedirectRegex: `(?i)/sso/start`,
			BodyRegex:     `(?i)session (has )?expired`,
		},
	}
	json := func(status int, body string) *ProbeResponse {
		return probe(status, body, "Content-Type", "application/json")
	}

	t.Run("logged_in holds with credentials, fails without", func(t *testing.T) {
		a := AssessAuthenticated(json(200, `{"email":"a@b"}`), json(200, `{"guest":true}`), check)
		assert.Equal(t, VerdictAuthenticated, a.Verdict, a.Reason)
		assert.Contains(t, signalNames(a), SignalConfiguredLoggedIn+":auth")
	})
	t.Run("logged_in also holds anonymously", func(t *testing.T) {
		a := AssessAuthenticated(json(200, `{"email":"a@b"}`), json(200, `{"email":null}`), check)
		assert.Equal(t, VerdictIndistinguishable, a.Verdict, a.Reason)
	})
	t.Run("logged_in fails on header", func(t *testing.T) {
		a := AssessAuthenticated(probe(200, `{"email":"a@b"}`, "Content-Type", "text/html"), json(401, ``), check)
		assert.Equal(t, VerdictUnauthorized, a.Verdict, a.Reason)
		assert.Contains(t, a.Reason, "header_regex")
	})
	t.Run("logged_in fails and the response is a login form", func(t *testing.T) {
		a := AssessAuthenticated(probe(200, loginPage), probe(200, loginPage), check)
		assert.Equal(t, VerdictLoginWall, a.Verdict, a.Reason)
	})
	t.Run("configured logged_out status", func(t *testing.T) {
		a := AssessAuthenticated(json(419, `{}`), json(419, `{}`), check)
		assert.Equal(t, VerdictUnauthorized, a.Verdict, a.Reason)
		assert.Contains(t, signalNames(a), SignalConfiguredLogOut+":auth")
	})
	t.Run("configured logged_out redirect (not a stock login path)", func(t *testing.T) {
		a := AssessAuthenticated(probe(302, "", "Location", "/sso/start?x=1"), probe(302, "", "Location", "/sso/start?x=1"), check)
		assert.Equal(t, VerdictLoginWall, a.Verdict, a.Reason)
	})
	t.Run("configured logged_out body", func(t *testing.T) {
		a := AssessAuthenticated(json(200, `{"error":"Session has expired"}`), json(200, `{}`), check)
		assert.Equal(t, VerdictLoginWall, a.Verdict, a.Reason)
	})
	t.Run("logged_out only, anon matches it", func(t *testing.T) {
		c := &SessionCheck{LoggedOut: &LoggedOutRule{Status: []int{419}}}
		a := AssessAuthenticated(probe(200, publicPage), probe(419, publicPage), c)
		assert.Equal(t, VerdictAuthenticated, a.Verdict, a.Reason)
	})
	t.Run("invalid regex is an error verdict", func(t *testing.T) {
		c := &SessionCheck{URL: "/x", LoggedIn: &LoggedInRule{BodyRegex: "("}}
		a := AssessAuthenticated(probe(200, dashboard), probe(200, publicPage), c)
		assert.Equal(t, VerdictError, a.Verdict)
	})
}

func TestCheckMatcher_LoggedOutSampling(t *testing.T) {
	m, err := (&SessionCheck{LoggedOut: &LoggedOutRule{Status: []int{401}, BodyRegex: "expired"}}).Compile()
	require.NoError(t, err)
	out, how := m.LoggedOut(probe(200, "session expired"), false)
	assert.False(t, out, "body regex skipped when not sampled")
	out, how = m.LoggedOut(probe(200, "session expired"), true)
	assert.True(t, out)
	assert.Equal(t, "body", how)
	out, how = m.LoggedOut(probe(401, ""), false)
	assert.True(t, out)
	assert.Equal(t, "status", how)

	var nilM *CheckMatcher
	out, _ = nilM.LoggedOut(probe(401, ""), true)
	assert.False(t, out)
}

func TestBodySimilarity(t *testing.T) {
	assert.Equal(t, 1.0, BodySimilarity(nil, nil))
	assert.Equal(t, 0.0, BodySimilarity([]byte("a"), nil))
	assert.Equal(t, 1.0, BodySimilarity([]byte(publicPage), []byte(publicPage)))
	assert.Less(t, BodySimilarity([]byte(dashboard), []byte(publicPage)), 0.6)
}

const checkYAML = `
sessions:
  - name: admin
    role: primary
    login:
      url: https://app.test/login
      method: POST
      body: u=a&p=b
      type: cookie
    check:
      url: /api/me
      method: get
      logged_in:
        status: [200]
        body_contains: '"email"'
        header_regex: 'Content-Type: application/json'
      logged_out:
        status: [401, 419, 440]
        redirect_regex: '(?i)/(login|signin|sso)\b'
        body_regex: '(?i)(session (has )?expired|please (log|sign) in)'
      sample_every: 25
      interval: 2m
    reauth:
      enabled: true
      max_attempts: 5
      backoff: 15s
      on_failure: abort
      pause_traffic: false
`

func TestParseSessionCheckBlock(t *testing.T) {
	sessions, issues, err := ParseSessionBytes([]byte(checkYAML), "s.yaml", ParseOptions{Strict: true})
	require.NoError(t, err)
	require.Empty(t, issues)
	require.Len(t, sessions, 1)
	s := sessions[0]
	require.NoError(t, s.Validate())
	require.NotNil(t, s.Check)
	assert.Equal(t, "/api/me", s.Check.URL)
	assert.Equal(t, "GET", s.Check.EffectiveMethod())
	assert.Equal(t, []int{200}, s.Check.LoggedIn.Status)
	assert.Equal(t, []int{401, 419, 440}, s.Check.LoggedOut.Status)
	assert.Equal(t, 25, s.Check.EffectiveSampleEvery())
	assert.Equal(t, 2*time.Minute, s.Check.Interval.D())
	require.NotNil(t, s.Reauth)
	assert.True(t, s.ReauthEnabled())
	assert.Equal(t, 5, s.Reauth.EffectiveMaxAttempts())
	assert.Equal(t, 15*time.Second, s.Reauth.EffectiveBackoff())
	assert.Equal(t, ReauthAbort, s.Reauth.EffectiveOnFailure())
	assert.False(t, s.Reauth.EffectivePauseTraffic())

	// The JSON form decodes the same durations.
	js := `{"name":"api","headers":{"Authorization":"Bearer x"},
	        "check":{"url":"https://app.test/me","interval":"90s","logged_in":{"status":[200]}},
	        "reauth":{"backoff":30}}`
	sessions, issues, err = ParseSessionBytes([]byte(js), "s.json", ParseOptions{Strict: true})
	require.NoError(t, err)
	require.Empty(t, issues)
	assert.Equal(t, 90*time.Second, sessions[0].Check.Interval.D())
	assert.Equal(t, 30*time.Second, sessions[0].Reauth.EffectiveBackoff())
	assert.False(t, sessions[0].ReauthEnabled(), "static headers cannot be re-logged in")
}

func TestReauthDefaults(t *testing.T) {
	var r *SessionReauth
	assert.Equal(t, DefaultReauthMaxAttempts, r.EffectiveMaxAttempts())
	assert.Equal(t, DefaultReauthBackoff, r.EffectiveBackoff())
	assert.Equal(t, ReauthContinue, r.EffectiveOnFailure(), "D19: continue is the default")
	assert.True(t, r.EffectivePauseTraffic())

	s := &Session{Name: "a", Login: &LoginFlow{URL: "https://x/login", Method: "POST", Type: LoginTypeCookie}}
	assert.False(t, s.ReauthEnabled(), "no check block, nothing to notice a logout")
	s.Check = &SessionCheck{URL: "/me"}
	assert.True(t, s.ReauthEnabled(), "enabled by default once a check exists")
	off := false
	s.Reauth = &SessionReauth{Enabled: &off}
	assert.False(t, s.ReauthEnabled())
}

func TestParseSessionCheck_UnknownFieldHasLine(t *testing.T) {
	doc := "name: a\nheaders: {X: y}\ncheck:\n  url: /me\n  loged_in:\n    status: [200]\n"
	d, err := ParseSessionDocument([]byte(doc), "s.yaml", ParseOptions{Strict: true})
	require.NoError(t, err)
	require.Len(t, d.Issues, 1)
	assert.Equal(t, "check.loged_in", d.Issues[0].Field)
	assert.Equal(t, 5, d.Issues[0].Line)
	assert.Contains(t, d.Issues[0].Message, `did you mean "logged_in"`)
}

func TestLintCheckAndReauth(t *testing.T) {
	lint := func(doc string) []LintIssue {
		t.Helper()
		d, err := ParseSessionDocument([]byte(doc), "s.yaml", ParseOptions{Strict: true})
		require.NoError(t, err)
		return append(d.Issues, d.Lint()...)
	}
	has := func(issues []LintIssue, sev, field, msg string) bool {
		for _, is := range issues {
			if is.Severity == sev && is.Field == field && strings.Contains(is.Message, msg) {
				return true
			}
		}
		return false
	}
	base := "name: a\nlogin:\n  url: https://app.test/login\n  method: POST\n  type: cookie\n"

	issues := lint(base + "check:\n  logged_in:\n    status: [200]\n")
	assert.True(t, has(issues, "error", "check.url", "required unless logged_out"), "%v", issues)
	// A position from the check block, not 0.
	for _, is := range issues {
		if is.Field == "check.url" {
			assert.Equal(t, 6, is.Line)
		}
	}

	issues = lint(base + "check:\n  logged_out:\n    status: [401]\n")
	assert.False(t, has(issues, "error", "check.url", ""), "status indicator makes url optional: %v", issues)

	issues = lint(base + "check:\n  url: api/me\n  method: 'GE T'\n  sample_every: -1\n  interval: -5s\n" +
		"  logged_in:\n    status: [999]\n    body_regex: '('\n  logged_out:\n    redirect_regex: '[a'\n")
	assert.True(t, has(issues, "error", "check.url", "path starting with"))
	assert.True(t, has(issues, "error", "check.method", "invalid HTTP method"))
	assert.True(t, has(issues, "error", "check.sample_every", ">= 1"))
	assert.True(t, has(issues, "error", "check.interval", "negative"))
	assert.True(t, has(issues, "error", "check.logged_in.status[0]", "999"))
	assert.True(t, has(issues, "error", "check.logged_in.body_regex", "invalid regex"))
	assert.True(t, has(issues, "error", "check.logged_out.redirect_regex", "invalid regex"))

	issues = lint(base + "reauth:\n  on_failure: retry\n  max_attempts: -2\n")
	assert.True(t, has(issues, "error", "reauth.on_failure", `"continue" or "abort"`))
	assert.True(t, has(issues, "error", "reauth.max_attempts", ">= 1"))
	assert.True(t, has(issues, "warning", "reauth", "without a check block"))

	issues = lint("name: s\nheaders: {X: y}\ncheck:\n  url: /me\nreauth:\n  backoff: 5s\n")
	assert.True(t, has(issues, "warning", "reauth", "static headers"))

	// Bundle paths carry the session index.
	issues = lint("sessions:\n  - name: a\n    headers: {X: y}\n    check:\n      url: ftp://x/me\n")
	assert.True(t, has(issues, "error", "sessions[0].check.url", "http or https"), "%v", issues)
}

func TestSessionValidate_CheckErrors(t *testing.T) {
	s := &Session{Name: "a", Headers: map[string]string{"X": "y"}, Check: &SessionCheck{URL: "/me", LoggedOut: &LoggedOutRule{BodyRegex: "("}}}
	err := s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check.logged_out.body_regex")

	s.Check.LoggedOut.BodyRegex = "expired"
	s.Reauth = &SessionReauth{OnFailure: "explode"}
	err = s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reauth.on_failure")

	s.Reauth.OnFailure = ReauthContinue
	require.NoError(t, s.Validate(), "warnings do not fail Validate")
}

func TestApplyDefaults(t *testing.T) {
	d := SessionDefaults{ValidateURL: "/api/me", ReauthOnStatus: []int{401, 440}, ReauthInterval: 5 * time.Minute}

	s := &Session{Name: "a"}
	s.ApplyDefaults(d)
	require.NotNil(t, s.Check)
	assert.Equal(t, "/api/me", s.Check.URL)
	assert.Equal(t, []int{401, 440}, s.Check.LoggedOut.Status)
	assert.Equal(t, 5*time.Minute, s.Check.Interval.D())

	own := &SessionCheck{URL: "/me", Interval: Duration(time.Minute), LoggedOut: &LoggedOutRule{Status: []int{419}, BodyRegex: "x"}}
	s = &Session{Name: "b", Check: own}
	s.ApplyDefaults(d)
	assert.Equal(t, "/me", s.Check.URL, "a session's own value wins")
	assert.Equal(t, []int{419}, s.Check.LoggedOut.Status)
	assert.Equal(t, time.Minute, s.Check.Interval.D())

	s = &Session{Name: "c", Check: &SessionCheck{LoggedOut: &LoggedOutRule{BodyRegex: "expired"}}}
	orig := s.Check
	s.ApplyDefaults(d)
	assert.Equal(t, []int{401, 440}, s.Check.LoggedOut.Status)
	assert.Equal(t, "expired", s.Check.LoggedOut.BodyRegex)
	assert.Nil(t, orig.LoggedOut.Status, "the original block is not mutated")

	s = &Session{Name: "d"}
	s.ApplyDefaults(SessionDefaults{})
	assert.Nil(t, s.Check, "empty defaults add nothing")
}

func TestResolveCheckURL(t *testing.T) {
	u, err := ResolveCheckURL("/api/me", "https://app.test:8443/auth/login?x=1")
	require.NoError(t, err)
	assert.Equal(t, "https://app.test:8443/api/me", u)
	u, err = ResolveCheckURL("http://other.test/me", "")
	require.NoError(t, err)
	assert.Equal(t, "http://other.test/me", u)
	_, err = ResolveCheckURL("/me", "")
	require.Error(t, err)
	_, err = ResolveCheckURL("ftp://x/me", "")
	require.Error(t, err)
}
