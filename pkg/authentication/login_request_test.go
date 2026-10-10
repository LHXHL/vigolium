package authentication

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loginRequestSessionFile writes an auth file whose only auth source is a raw
// login_request aimed at srv, and returns its path.
func loginRequestSessionFile(t *testing.T, srv *httptest.Server, path, body string) string {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	raw := fmt.Sprintf("POST %s%s HTTP/1.1\nHost: %s\nContent-Type: application/json\nX-Requested-With: XMLHttpRequest\n\n%s",
		srv.URL, path, host, body)
	var b strings.Builder
	b.WriteString("sessions:\n  - name: admin\n    role: primary\n    login_request: |\n")
	for _, line := range strings.Split(raw, "\n") {
		b.WriteString("      " + line + "\n")
	}
	file := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	return file
}

// TestLoginRequestSession_LogsInDuringScan is the regression guard for sessions
// that carry only a login_request: they validated and loaded, then
// HydrateSessions skipped them (no Login) and the scan ran anonymously. Loaded
// through the same path a scan uses, such a session must now send its raw
// request — headers included — and pick up the token from the response.
func TestLoginRequestSession_LogsInDuringScan(t *testing.T) {
	var logins int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/user/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Requested-With") != "XMLHttpRequest" ||
			r.Header.Get("Content-Type") != "application/json" ||
			!strings.Contains(string(body), `"admin@example.test"`) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logins++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authentication":{"token":"tok-123"}}`))
	}))
	defer srv.Close()

	file := loginRequestSessionFile(t, srv, "/rest/user/login", `{"email":"admin@example.test","password":"pw"}`)
	sessions, err := LoadFromAuthFiles([]string{file}, "")
	if err != nil {
		t.Fatalf("LoadFromAuthFiles: %v", err)
	}
	mgr, err := NewManager(sessions)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.HydrateSessionsContext(context.Background()); err != nil {
		t.Fatalf("HydrateSessionsContext: %v", err)
	}

	if logins != 1 {
		t.Fatalf("login endpoint hit %d time(s), want 1", logins)
	}
	if got := mgr.Primary().Headers["Authorization"]; got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer tok-123")
	}
}

// TestNewManager_ConvertedSessionRevalidates: the LoginFlow converted from
// login_request is the same auth source, so building a second manager from the
// same (not yet hydrated) sessions must not reject them as having two.
func TestNewManager_ConvertedSessionRevalidates(t *testing.T) {
	sessions := []*Session{{Name: "x", LoginRequest: "POST http://127.0.0.1:1/login HTTP/1.1\nHost: 127.0.0.1:1\n\n{}"}}
	if _, err := NewManager(sessions); err != nil {
		t.Fatalf("first NewManager: %v", err)
	}
	if sessions[0].Login == nil {
		t.Fatal("login_request was not converted to a LoginFlow")
	}
	if _, err := NewManager(sessions); err != nil {
		t.Fatalf("second NewManager rejected the converted session: %v", err)
	}
}

// TestLoginRequestSession_CookieLogin: a form login that answers with
// Set-Cookie on a redirect yields a Cookie header.
func TestLoginRequestSession_CookieLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s3cr3t", Path: "/"})
			http.Redirect(w, r, "/home", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	file := loginRequestSessionFile(t, srv, "/login", `{"user":"a"}`)
	sessions, err := LoadFromAuthFiles([]string{file}, "")
	if err != nil {
		t.Fatalf("LoadFromAuthFiles: %v", err)
	}
	mgr, err := NewManager(sessions)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.HydrateSessionsContext(context.Background()); err != nil {
		t.Fatalf("HydrateSessionsContext: %v", err)
	}
	if got := mgr.Primary().Headers["Cookie"]; got != "sid=s3cr3t" {
		t.Errorf("Cookie = %q, want %q", got, "sid=s3cr3t")
	}
}

// TestLoginRequestSession_NoTokenFails: a login whose response carries nothing
// that looks like a credential is a failed login, not a silent anonymous scan.
func TestLoginRequestSession_NoTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	file := loginRequestSessionFile(t, srv, "/login", `{}`)
	sessions, err := LoadFromAuthFiles([]string{file}, "")
	if err != nil {
		t.Fatalf("LoadFromAuthFiles: %v", err)
	}
	mgr, err := NewManager(sessions)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	err = mgr.HydrateSessionsContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no auth tokens") {
		t.Fatalf("HydrateSessionsContext error = %v, want a no-auth-tokens failure", err)
	}
}

// TestNewManager_BadLoginRequestIsAnError: an unparseable login_request used to
// be ignored along with every other one; now that it is used, a broken one is
// reported when the session is loaded.
func TestNewManager_BadLoginRequestIsAnError(t *testing.T) {
	_, err := NewManager([]*Session{{Name: "x", LoginRequest: "POST /login HTTP/1.1\n\n{}"}})
	if err == nil || !strings.Contains(err.Error(), "login_request") {
		t.Fatalf("NewManager error = %v, want a login_request parse error", err)
	}
}
