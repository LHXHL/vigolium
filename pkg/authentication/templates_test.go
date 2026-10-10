package authentication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 6238 appendix B: the SHA-1 secret "12345678901234567890" at T=59s gives
// 94287082; the 6-digit code is its last six digits.
const (
	rfcTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	rfcTOTPCode   = "287082"
)

func freezeTemplateClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := templateNow
	templateNow = func() time.Time { return at }
	t.Cleanup(func() { templateNow = prev })
}

func TestExpandTemplates(t *testing.T) {
	freezeTemplateClock(t, time.Unix(59, 0))
	t.Setenv("G16B_TOTP", rfcTOTPSecret)
	t.Setenv("G16B_USER", "alice")
	secretFile := filepath.Join(t.TempDir(), "totp.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("  "+rfcTOTPSecret+"\n"), 0o600))

	got, err := expandTemplates(`{"user":"{{env:G16B_USER}}","otp":"{{ totp:G16B_TOTP }}","otp2":"{{totp_secret_file:` + secretFile + `}}"}`)
	require.NoError(t, err)
	assert.Equal(t, `{"user":"alice","otp":"`+rfcTOTPCode+`","otp2":"`+rfcTOTPCode+`"}`, got)

	// No template: unchanged, including single-brace step variables.
	got, err = expandTemplates("csrf={csrf}")
	require.NoError(t, err)
	assert.Equal(t, "csrf={csrf}", got)

	for _, bad := range []string{"{{env:G16B_NOT_SET_ANYWHERE}}", "{{totp:G16B_NOT_SET_ANYWHERE}}", "{{totp_secret_file:/nonexistent/g16b}}", "{{shell:id}}"} {
		_, err := expandTemplates(bad)
		assert.Error(t, err, bad)
	}
	t.Setenv("G16B_BAD_SECRET", "not base32 !!")
	_, err = expandTemplates("{{totp:G16B_BAD_SECRET}}")
	assert.ErrorContains(t, err, "invalid TOTP secret")
}

// Variables a step extracted are substituted after templates, so a value the
// server returned is never itself expanded.
func TestSubstituteVars_TemplatesBeforeVars(t *testing.T) {
	t.Setenv("G16B_USER", "alice")
	got, err := substituteVars("{{env:G16B_USER}}:{tok}", map[string]string{"tok": "{{env:G16B_USER}}"})
	require.NoError(t, err)
	assert.Equal(t, "alice:{{env:G16B_USER}}", got)
}

func TestLintTemplates(t *testing.T) {
	sev := func(s string) []string {
		var out []string
		for _, is := range lintTemplates(s, "login.body") {
			out = append(out, is.Severity)
		}
		return out
	}
	assert.Empty(t, sev("{{totp:MFA_SECRET}} {{env:PASS}} {{totp_secret_file:~/otp}}"))
	assert.Equal(t, []string{"warning"}, sev("{{totp:"+rfcTOTPSecret+"}}"), "literal base32 secret")
	assert.Equal(t, []string{"error"}, sev("{{totp:}}"))
	assert.Equal(t, []string{"error"}, sev("{{env:not a name}}"))
	assert.Equal(t, []string{"error"}, sev("{{exec:id}}"))

	// Reached through session lint, with the field path.
	issues := lintSession(&Session{Name: "a", Login: &LoginFlow{
		Steps: []LoginStep{{URL: "https://x/login", Method: "POST",
			Headers: map[string]string{"X-OTP": "{{totp:" + rfcTOTPSecret + "}}"},
			Extract: []ExtractRule{{Source: ExtractCookie}}}},
	}}, "")
	require.Len(t, issues, 1)
	assert.Equal(t, "login.steps[0].headers.X-OTP", issues[0].Field)
	assert.Equal(t, "warning", issues[0].Severity)
}

// A two-step login whose flow and step headers (with a TOTP template and an
// extracted variable) reach the server; the step header wins on a clash.
func TestMultiStepLogin_PerStepHeaders(t *testing.T) {
	freezeTemplateClock(t, time.Unix(59, 0))
	t.Setenv("G16B_TOTP", rfcTOTPSecret)

	var mu sync.Mutex
	seen := map[string]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Clone()
		mu.Unlock()
		switch r.URL.Path {
		case "/start":
			_, _ = w.Write([]byte(`{"challenge":"c-42"}`))
		case "/verify":
			if r.Header.Get("X-OTP") != rfcTOTPCode || r.Header.Get("X-Challenge") != "c-42" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"token":"tkn"}`))
		}
	}))
	defer srv.Close()

	sess := &Session{Name: "mfa", Login: &LoginFlow{
		Headers: map[string]string{"X-Client": "vigolium", "X-Mode": "flow"},
		Steps: []LoginStep{
			{URL: srv.URL + "/start", Method: "POST", Body: `{}`,
				Extract: []ExtractRule{{Source: ExtractJSON, Path: ".challenge", ApplyAs: "var:challenge"}}},
			{URL: srv.URL + "/verify", Method: "POST", Body: `{}`,
				Headers: map[string]string{"X-OTP": "{{totp:G16B_TOTP}}", "X-Challenge": "{challenge}", "X-Mode": "step"},
				Expect:  &ExpectResponse{Status: []int{200}},
				Extract: []ExtractRule{{Source: ExtractJSON, Path: ".token", ApplyAs: "Authorization: Bearer {value}"}}},
		},
	}}
	res := CheckLogin(context.Background(), sess, nil)
	require.True(t, res.OK, res.Message)
	assert.Equal(t, "Bearer tkn", sess.Headers["Authorization"])

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "vigolium", seen["/start"].Get("X-Client"), "flow headers go on every step")
	assert.Equal(t, "flow", seen["/start"].Get("X-Mode"))
	assert.Empty(t, seen["/start"].Get("X-OTP"))
	assert.Equal(t, "vigolium", seen["/verify"].Get("X-Client"))
	assert.Equal(t, "step", seen["/verify"].Get("X-Mode"), "a step header wins over the flow's")
	assert.Equal(t, rfcTOTPCode, seen["/verify"].Get("X-OTP"))
}

// login.headers on a single-request flow, with templates in url and body.
func TestSingleStepLogin_HeadersAndTemplates(t *testing.T) {
	t.Setenv("G16B_PASS", "pw")
	var gotKey, gotBody, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		gotPath = r.URL.RawQuery
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}))
	defer srv.Close()

	sess := &Session{Name: "a", Login: &LoginFlow{
		URL: srv.URL + "/login?tenant={{env:G16B_PASS}}", Method: "POST", Body: "p={{env:G16B_PASS}}",
		Type: LoginTypeBearer, TokenPath: ".token",
		Headers: map[string]string{"X-Api-Key": "k-{{env:G16B_PASS}}"},
	}}
	require.NoError(t, executeLogin(context.Background(), sess, nil))
	assert.Equal(t, "k-pw", gotKey)
	assert.Equal(t, "p=pw", gotBody)
	assert.Equal(t, "tenant=pw", gotPath)
	assert.Equal(t, "p={{env:G16B_PASS}}", sess.Login.Body, "the flow keeps its template for the next login")
}
