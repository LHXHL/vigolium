package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenServer is an OAuth2 token endpoint. client_credentials needs
// scanner/s3cret (Basic auth or form fields); refresh_token needs the current
// refresh token and rotates it. Every grant mints access token at-<n>.
type tokenServer struct {
	srv       *httptest.Server
	expiresIn int
	minted    atomic.Int64

	mu       sync.Mutex
	refresh  string // the refresh token the server accepts
	requests []tokenRequest
}

type tokenRequest struct {
	at       time.Time
	style    string // "header" or "body"
	grant    string
	scope    string
	audience string
	refresh  string
	extraHdr string
}

func newTokenServer(t *testing.T, expiresIn int) *tokenServer {
	t.Helper()
	ts := &tokenServer{expiresIn: expiresIn, refresh: "rt-1"}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		req := tokenRequest{
			at: time.Now(), grant: r.PostForm.Get("grant_type"), scope: r.PostForm.Get("scope"),
			audience: r.PostForm.Get("audience"), refresh: r.PostForm.Get("refresh_token"),
			extraHdr: r.Header.Get("X-Tenant"),
		}
		id, secret, basic := r.BasicAuth()
		if basic {
			req.style = "header"
		} else {
			req.style = "body"
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		ts.mu.Lock()
		ts.requests = append(ts.requests, req)
		ts.mu.Unlock()

		fail := func(code string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
		}
		if id != "scanner" || secret != "s3cret" {
			fail("invalid_client")
			return
		}
		resp := map[string]any{"token_type": "bearer"}
		switch req.grant {
		case "client_credentials":
		case "refresh_token":
			ts.mu.Lock()
			ok := req.refresh == ts.refresh
			if ok {
				ts.refresh = fmt.Sprintf("rt-%d", ts.minted.Load()+2)
				resp["refresh_token"] = ts.refresh
			}
			ts.mu.Unlock()
			if !ok {
				fail("invalid_grant")
				return
			}
		default:
			fail("unsupported_grant_type")
			return
		}
		resp["access_token"] = fmt.Sprintf("at-%d", ts.minted.Add(1))
		if ts.expiresIn > 0 {
			resp["expires_in"] = ts.expiresIn
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) reqs() []tokenRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]tokenRequest(nil), ts.requests...)
}

func (ts *tokenServer) clientCredentials(style string) *Session {
	return &Session{
		Name: "svc",
		Login: &LoginFlow{
			Type:         LoginTypeOAuth2ClientCredentials,
			TokenURL:     ts.srv.URL + "/token",
			ClientID:     "scanner",
			ClientSecret: "{{env:G16B_TEST_CLIENT_SECRET}}",
			Scope:        "read write",
			Audience:     "https://api.example.test",
			AuthStyle:    style,
			Headers:      map[string]string{"X-Tenant": "acme"},
		},
	}
}

func TestOAuth2ClientCredentials_AuthStyles(t *testing.T) {
	t.Setenv("G16B_TEST_CLIENT_SECRET", "s3cret")
	for _, style := range []string{OAuth2AuthStyleHeader, OAuth2AuthStyleBody} {
		t.Run(style, func(t *testing.T) {
			ts := newTokenServer(t, 3600)
			sess := ts.clientCredentials(style)
			m, err := NewManager([]*Session{sess})
			require.NoError(t, err)
			before := time.Now()
			require.NoError(t, m.HydrateSessions())

			assert.Equal(t, "Bearer at-1", sess.Headers["Authorization"])
			exp := sess.ExpiresAt()
			assert.WithinDuration(t, before.Add(time.Hour), exp, 5*time.Second)

			reqs := ts.reqs()
			require.Len(t, reqs, 1)
			assert.Equal(t, style, reqs[0].style)
			assert.Equal(t, "client_credentials", reqs[0].grant)
			assert.Equal(t, "read write", reqs[0].scope)
			assert.Equal(t, "https://api.example.test", reqs[0].audience)
			assert.Equal(t, "acme", reqs[0].extraHdr, "login.headers ride on the token request")
		})
	}
}

func TestOAuth2_CheckLoginReportsExpiry(t *testing.T) {
	t.Setenv("G16B_TEST_CLIENT_SECRET", "s3cret")
	ts := newTokenServer(t, 600)
	sess := ts.clientCredentials("")
	res := CheckLogin(context.Background(), sess, nil)
	require.True(t, res.OK, res.Message)
	assert.True(t, res.Verified)
	assert.Equal(t, http.StatusOK, res.Status)
	assert.Equal(t, []string{"Authorization"}, res.ExtractedHeaders)
	require.NotNil(t, res.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), *res.ExpiresAt, 5*time.Second)
}

func TestOAuth2_BadClientFails(t *testing.T) {
	t.Setenv("G16B_TEST_CLIENT_SECRET", "wrong")
	ts := newTokenServer(t, 60)
	res := CheckLogin(context.Background(), ts.clientCredentials(OAuth2AuthStyleHeader), nil)
	assert.False(t, res.OK)
	assert.Equal(t, LoginReasonUnexpectedStatus, res.Reason)
	assert.Contains(t, res.Message, "invalid_client")
}

func TestOAuth2_MissingEnvTemplateFails(t *testing.T) {
	ts := newTokenServer(t, 60)
	res := CheckLogin(context.Background(), ts.clientCredentials(OAuth2AuthStyleHeader), nil)
	assert.False(t, res.OK)
	assert.Equal(t, LoginReasonInvalidFlow, res.Reason)
	assert.Contains(t, res.Message, "G16B_TEST_CLIENT_SECRET")
	assert.Empty(t, ts.reqs(), "no token request with an unresolved secret")
}

func TestOAuth2RefreshToken_RotatesAcrossRehydrate(t *testing.T) {
	ts := newTokenServer(t, 3600)
	sess := &Session{
		Name: "user",
		Login: &LoginFlow{
			Type: LoginTypeOAuth2RefreshToken, TokenURL: ts.srv.URL + "/token",
			ClientID: "scanner", ClientSecret: "s3cret", RefreshToken: "rt-1", AuthStyle: OAuth2AuthStyleBody,
		},
	}
	m, err := NewManager([]*Session{sess})
	require.NoError(t, err)
	require.NoError(t, m.HydrateSessions())
	assert.Equal(t, "Bearer at-1", sess.Headers["Authorization"])
	assert.Equal(t, "rt-2", sess.Login.RefreshToken, "rotated refresh token kept")

	h, exp, err := m.rehydrate(context.Background(), "user")
	require.NoError(t, err)
	assert.Equal(t, "Bearer at-2", h["Authorization"])
	assert.False(t, exp.IsZero())
	assert.Equal(t, "rt-3", sess.Login.RefreshToken, "Rehydrate writes the rotation back")

	reqs := ts.reqs()
	require.Len(t, reqs, 2)
	assert.Equal(t, "rt-1", reqs[0].refresh)
	assert.Equal(t, "rt-2", reqs[1].refresh)
	assert.Equal(t, "refresh_token", reqs[1].grant)
}

// An OAuth2 session with no check block still gets a LiveSession, which
// refreshes the token BEFORE it expires (no 401 needed) and does not park
// traffic while it does.
func TestLiveSession_ProactiveRefreshBeforeExpiry(t *testing.T) {
	t.Setenv("G16B_TEST_CLIENT_SECRET", "s3cret")
	ts := newTokenServer(t, 2) // lead = half the 2s lifetime: refresh at ~1s
	sess := ts.clientCredentials(OAuth2AuthStyleHeader)
	ls, _, log := newLive(t, sess, LiveOptions{})

	first := ls.Credentials()
	require.Equal(t, uint64(1), first.Gen)
	require.False(t, first.ExpiresAt.IsZero())
	assert.Equal(t, "Bearer at-1", first.Headers["Authorization"])

	waitUntil(t, "proactive refresh", func() bool { return ls.Credentials().Gen == 2 })
	reqs := ts.reqs()
	require.Len(t, reqs, 2)
	assert.True(t, reqs[1].at.Before(first.ExpiresAt), "refreshed at %s, token expired at %s", reqs[1].at, first.ExpiresAt)
	assert.Equal(t, "Bearer at-2", ls.Credentials().Headers["Authorization"])
	assert.Equal(t, LiveValid, ls.State())

	log.mu.Lock()
	require.NotEmpty(t, log.evs)
	assert.Equal(t, "expiry", log.evs[0].Reason)
	log.mu.Unlock()
	assert.Equal(t, []string{"suspect", "relogin:true"}, log.kinds()[:2])
}

func TestExpiryLead(t *testing.T) {
	at := time.Unix(1000, 0)
	assert.Equal(t, 60*time.Second, expiryLead(at, at.Add(time.Hour)))
	assert.Equal(t, 30*time.Second, expiryLead(at, at.Add(300*time.Second)))
	assert.Equal(t, 5*time.Second, expiryLead(at, at.Add(20*time.Second)))
	assert.Equal(t, time.Second, expiryLead(at, at.Add(2*time.Second)))
	assert.Equal(t, time.Duration(0), expiryLead(at, at.Add(-time.Second)))
}

func TestLintOAuth2Flow(t *testing.T) {
	issues := lintLoginFlow(&LoginFlow{Type: LoginTypeOAuth2ClientCredentials, AuthStyle: "query", URL: "https://x/login"}, "login")
	byField := map[string]string{}
	for _, is := range issues {
		byField[is.Field] = is.Severity
	}
	assert.Equal(t, "error", byField["login.token_url"])
	assert.Equal(t, "error", byField["login.client_id"])
	assert.Equal(t, "error", byField["login.client_secret"])
	assert.Equal(t, "error", byField["login.auth_style"])
	assert.Equal(t, "warning", byField["login.url"], "request-flow fields are ignored")

	issues = lintLoginFlow(&LoginFlow{Type: LoginTypeOAuth2RefreshToken, TokenURL: "ftp://idp/token"}, "login")
	byField = map[string]string{}
	for _, is := range issues {
		byField[is.Field] = is.Severity
	}
	assert.Equal(t, "error", byField["login.token_url"])
	assert.Equal(t, "error", byField["login.refresh_token"])

	ok := &LoginFlow{Type: LoginTypeOAuth2ClientCredentials, TokenURL: "https://idp/token", ClientID: "a", ClientSecret: "{{env:SECRET}}"}
	assert.Empty(t, lintLoginFlow(ok, "login"))
	assert.NoError(t, ok.Validate("svc"))

	err := (&LoginFlow{Type: LoginTypeOAuth2RefreshToken, TokenURL: "https://idp/token"}).Validate("svc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh_token")

	// OAuth2 fields on a non-OAuth2 flow do nothing: warn.
	warn := lintLoginFlow(&LoginFlow{URL: "https://x/login", Method: "POST", Type: LoginTypeCookie, ClientSecret: "x"}, "login")
	require.NotEmpty(t, warn)
	assert.Equal(t, "warning", warn[0].Severity)
	assert.True(t, strings.Contains(warn[0].Message, "client_secret"))
}

// The new fields are part of the strict schema: a file using all of them
// parses and lints clean.
func TestParseSessionDocument_NewLoginFieldsStrict(t *testing.T) {
	doc, err := ParseSessionDocument([]byte(`sessions:
  - name: svc
    role: primary
    login:
      type: oauth2_client_credentials
      token_url: https://idp.example.test/token
      client_id: a
      client_secret: "{{env:SECRET}}"
      scope: "read write"
      audience: https://api.example.test
      auth_style: body
      headers: {X-Tenant: acme}
  - name: user
    role: compare
    login:
      headers: {Origin: "https://app.example.test"}
      steps:
        - url: https://app.example.test/login
          method: POST
          headers: {X-OTP: "{{totp:OTP_SECRET}}"}
          extract: [{source: cookie}]
`), "s.yaml", ParseOptions{Strict: true})
	require.NoError(t, err)
	assert.Empty(t, doc.Issues)
	assert.Empty(t, doc.Lint())
	assert.Equal(t, "body", doc.Sessions[0].Login.AuthStyle)
	assert.Equal(t, "{{totp:OTP_SECRET}}", doc.Sessions[1].Login.Steps[0].Headers["X-OTP"])
}
