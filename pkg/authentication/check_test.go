package authentication

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// formLoginServer is a classic form login: POST /login with pw=right sets a
// session cookie and redirects to /home; anything else re-renders the form
// (200, password input) after setting an anonymous cookie.
func formLoginServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "pw=right") {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "authed", Path: "/"})
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "anon", Value: "x", Path: "/"})
		_, _ = fmt.Fprint(w, `<form method=post><input name=u><input type="password" name=pw></form> invalid credentials`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `Welcome back`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func formSession(loginURL, body string, expect *ExpectResponse) *Session {
	return &Session{
		Name: "user",
		Role: RolePrimary,
		Login: &LoginFlow{
			URL: loginURL, Method: "POST", Body: body,
			ContentType: "application/x-www-form-urlencoded",
			Extract:     []ExtractRule{{Source: ExtractCookie}},
			Expect:      expect,
		},
	}
}

func TestCheckLogin_ExpectBodyFailsWrongPassword(t *testing.T) {
	srv := formLoginServer(t)
	res := CheckLogin(context.Background(), formSession(srv.URL+"/login", "u=a&pw=wrong", &ExpectResponse{BodyContains: "Welcome"}), nil)
	if res.OK {
		t.Fatalf("wrong password with expect.body_contains passed: %+v", res)
	}
	if res.Reason != LoginReasonExpectBody {
		t.Errorf("reason = %q, want %q", res.Reason, LoginReasonExpectBody)
	}
	if res.Status != 200 {
		t.Errorf("status = %d, want 200", res.Status)
	}
}

func TestCheckLogin_ExpectStatusMismatch(t *testing.T) {
	srv := formLoginServer(t)
	res := CheckLogin(context.Background(), formSession(srv.URL+"/login", "pw=wrong", &ExpectResponse{Status: []int{302}}), nil)
	if res.OK || res.Reason != LoginReasonExpectStatus {
		t.Fatalf("want expect_status_mismatch, got %+v", res)
	}
}

func TestCheckLogin_RightPasswordVerified(t *testing.T) {
	srv := formLoginServer(t)
	sess := formSession(srv.URL+"/login", "pw=right", &ExpectResponse{BodyContains: "Welcome"})
	res := CheckLogin(context.Background(), sess, nil)
	if !res.OK || !res.Verified || res.Reason != "" {
		t.Fatalf("want verified OK, got %+v", res)
	}
	if !strings.HasSuffix(res.FinalURL, "/home") || len(res.Redirects) != 1 {
		t.Errorf("final_url=%q redirects=%v, want one redirect to /home", res.FinalURL, res.Redirects)
	}
	if len(res.ExtractedHeaders) != 1 || res.ExtractedHeaders[0] != "Cookie" {
		t.Errorf("extracted = %v, want [Cookie]", res.ExtractedHeaders)
	}
	if !strings.Contains(sess.Headers["Cookie"], "sid=authed") {
		t.Errorf("session not hydrated: %v", sess.Headers)
	}
}

// No expect block: the wrong password still "extracts" the anonymous cookie, but
// the form came back — unverified (a warning), not OK-and-verified.
func TestCheckLogin_NoExpectLoginFormIsUnverified(t *testing.T) {
	srv := formLoginServer(t)
	res := CheckLogin(context.Background(), formSession(srv.URL+"/login", "pw=wrong", nil), nil)
	if !res.OK || res.Verified || res.Reason != LoginReasonUnverified {
		t.Fatalf("want OK unverified, got %+v", res)
	}
	if !strings.Contains(res.Message, "password field") {
		t.Errorf("message should name the login form: %q", res.Message)
	}
}

func TestCheckLogin_NoExpectRedirectAwayVerified(t *testing.T) {
	srv := formLoginServer(t)
	res := CheckLogin(context.Background(), formSession(srv.URL+"/login", "pw=right", nil), nil)
	if !res.OK || !res.Verified {
		t.Fatalf("want verified, got %+v", res)
	}
}

// The old probe returned 403 with no error; the check fails it.
func TestCheckLogin_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	res := CheckLogin(context.Background(), bearerSession("admin", srv.URL), nil)
	if res.OK || res.Reason != LoginReasonUnexpectedStatus || res.Status != http.StatusForbidden {
		t.Fatalf("want unexpected_status 403, got %+v", res)
	}
}

func TestCheckLogin_ExtractFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"nope":1}`)
	}))
	defer srv.Close()
	res := CheckLogin(context.Background(), bearerSession("admin", srv.URL), nil)
	if res.OK || res.Reason != LoginReasonExtractFailed {
		t.Fatalf("want extract_failed, got %+v", res)
	}
}

func TestCheckLogin_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	res := CheckLogin(context.Background(), bearerSession("admin", u), nil)
	if res.OK || res.Reason != LoginReasonNetworkError {
		t.Fatalf("want network_error, got %+v", res)
	}
}

// The old probe sent the parent login URL, which a multi-step flow leaves
// empty. The check runs every step, passes variables, and honours each
// step's expect.
func TestCheckLogin_MultiStep(t *testing.T) {
	var step1, step2 atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/step1", func(w http.ResponseWriter, r *http.Request) {
		step1.Add(1)
		_, _ = fmt.Fprint(w, `{"ist":"abc"}`)
	})
	mux.HandleFunc("/step2", func(w http.ResponseWriter, r *http.Request) {
		step2.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"abc"`) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"token":"final"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mk := func(expect2 *ExpectResponse) *Session {
		return &Session{Name: "ms", Role: RolePrimary, Login: &LoginFlow{Steps: []LoginStep{
			{URL: srv.URL + "/step1", Method: "POST", Body: `{}`, Expect: &ExpectResponse{Status: []int{200}},
				Extract: []ExtractRule{{Source: ExtractJSON, Path: "$.ist", ApplyAs: "var:ist"}}},
			{URL: srv.URL + "/step2", Method: "POST", Body: `{"ist":"{ist}"}`, Expect: expect2,
				Extract: []ExtractRule{{Source: ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}}},
		}}}
	}

	sess := mk(&ExpectResponse{BodyContains: "token"})
	res := CheckLogin(context.Background(), sess, nil)
	if !res.OK || !res.Verified {
		t.Fatalf("multi-step login: %+v", res)
	}
	if step1.Load() != 1 || step2.Load() != 1 {
		t.Errorf("steps hit %d/%d times, want 1/1", step1.Load(), step2.Load())
	}
	if res.Step == nil || *res.Step != 1 {
		t.Errorf("step = %v, want 1", res.Step)
	}
	if sess.Headers["Authorization"] != "Bearer final" {
		t.Errorf("headers = %v", sess.Headers)
	}

	// The last step's expect fails: the result names that step.
	res = CheckLogin(context.Background(), mk(&ExpectResponse{BodyContains: "never"}), nil)
	if res.OK || res.Reason != LoginReasonExpectBody || res.Step == nil || *res.Step != 1 {
		t.Fatalf("want step 1 expect_body_missing, got %+v", res)
	}
}

// The client's transport is used: a proxy configured on it sees the login.
func TestCheckLogin_UsesClientTransport(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"token":"via-proxy"}`)
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	res := CheckLogin(context.Background(), bearerSession("admin", "http://login.invalid/api/login"), client)
	if !res.OK || proxied.Load() != 1 {
		t.Fatalf("login did not go through the client's proxy: proxied=%d res=%+v", proxied.Load(), res)
	}
}

func TestCheckLogin_LoginRequestOnly(t *testing.T) {
	// A raw request line has no scheme; the parser assumes https.
	srv := httptest.NewTLSServer(tokenHandler(0))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	sess := &Session{Name: "raw", LoginRequest: "POST /login HTTP/1.1\r\nHost: " + u.Host + "\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"}
	res := CheckLogin(context.Background(), sess, srv.Client())
	if !res.OK || !res.Verified {
		t.Fatalf("login_request session: %+v", res)
	}
	if sess.Login != nil {
		t.Error("the session should keep login_request as its only login source")
	}
	if sess.Headers["Authorization"] != "Bearer tok-123" {
		t.Errorf("credentials not copied back: %v", sess.Headers)
	}
}

func TestCheckLogin_NoLogin(t *testing.T) {
	res := CheckLogin(context.Background(), &Session{Name: "static", Headers: map[string]string{"X": "y"}}, nil)
	if res.OK || res.Reason != LoginReasonInvalidFlow {
		t.Fatalf("want invalid_flow, got %+v", res)
	}
}
