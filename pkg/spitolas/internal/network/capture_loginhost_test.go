package network

import (
	"strings"
	"testing"
)

// TestNoteLoginHostCollectsChainHosts pins that the capture — the only layer
// that sees individual redirect hops — records every host serving an
// authentication endpoint. The crawler reads this to deny a whole SSO chain
// instead of only the host the browser came to rest on.
func TestNoteLoginHostCollectsChainHosts(t *testing.T) {
	c := New(&mockWriter{}, true, true, false, false, false, "app.acme.com", "spider")

	// A real OAuth bounce: the app redirects to an authorize endpoint on one
	// host, which redirects again to the login form on another.
	c.noteLoginHost("https://app.acme.com/")
	c.noteLoginHost("https://idp.acme.net/as/authorization.oauth2?client_id=x&response_type=code")
	c.noteLoginHost("https://sso.acme.com/u/login/identifier?state=abc")
	// Third-party subresources the login page pulls in are not auth endpoints.
	c.noteLoginHost("https://challenges.cloudflare.com/turnstile/v0/api.js")
	c.noteLoginHost("not a url at all")
	c.noteLoginHost("")

	got := c.LoginHostsSeen()
	want := []string{"idp.acme.net", "sso.acme.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("LoginHostsSeen() = %v, want %v", got, want)
	}
}

func TestLoginHostsSeenDedups(t *testing.T) {
	c := New(&mockWriter{}, true, true, false, false, false, "app.acme.com", "spider")
	for range 3 {
		c.noteLoginHost("https://sso.acme.com/login")
	}
	if got := c.LoginHostsSeen(); len(got) != 1 {
		t.Errorf("LoginHostsSeen() = %v, want one entry", got)
	}
}

// TestScopeFilterSuppressesLogEvenInVerbose is the log-noise fix. These entries
// are already dropped before storage, so printing them showed traffic no phase
// would ever scan — a login page's CAPTCHA widget reading as if the scanner
// were hammering somebody else's CDN. Verbose must not re-admit them.
func TestScopeFilterSuppressesLogEvenInVerbose(t *testing.T) {
	const verbose = true
	c := New(&mockWriter{}, true, false, verbose, false, false, "app.acme.com", "spider")
	c.ScopeFilter = func(host, _ string) bool {
		return strings.HasSuffix(host, "acme.com")
	}

	inScope := createTestEntry("https://app.acme.com/dashboard")
	if !c.shouldLogEntry(inScope) {
		t.Error("in-scope entry should be logged")
	}

	thirdParty := createTestEntry("https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/fo/123")
	if c.shouldLogEntry(thirdParty) {
		t.Error("out-of-scope entry must stay suppressed in verbose mode")
	}
}

func TestNoScopeFilterLeavesLoggingUnchanged(t *testing.T) {
	c := New(&mockWriter{}, true, false, true, false, false, "app.acme.com", "spider")
	if !c.shouldLogEntry(createTestEntry("https://third-party.example/beacon")) {
		t.Error("without a ScopeFilter, verbose mode should still log everything it did before")
	}
}
