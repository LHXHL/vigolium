package crawler

import (
	"context"
	"testing"
)

func TestDenyWallHostIsIdempotentAndCaseInsensitive(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")

	c.denyWallHost("SSO.Acme.com")
	c.denyWallHost("sso.acme.com")
	c.denyWallHost("")
	c.denyWallHost("   ")

	if got := c.wallHostList(); len(got) != 1 || got[0] != "sso.acme.com" {
		t.Errorf("wallHostList() = %v, want exactly [sso.acme.com]", got)
	}
	if !c.isWallHost("SSO.ACME.COM") {
		t.Error("isWallHost should be case-insensitive")
	}
	if c.isWallHost("app.acme.com") {
		t.Error("a host that was never denied must not be a wall host")
	}
}

// TestWallDenialOverridesCrawlScope is the regression this whole change exists
// for. A scan of app.acme.com bounces to the org's IdP at sso.acme.com. Every
// scope mode short of strict admits that host, so before the denial the crawler
// identified the wall, logged "supply --auth", and then crawled the IdP anyway.
func TestWallDenialOverridesCrawlScope(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")
	// The operator's scope admits the whole registrable domain.
	c.config.CrawlScope = func(string) bool { return true }

	if !c.inScopeURL("https://app.acme.com/dashboard") {
		t.Fatal("target URL should be in scope before any denial")
	}
	if !c.inScopeURL("https://sso.acme.com/login") {
		t.Fatal("precondition: the permissive scope rule admits the IdP host")
	}

	c.denyWallHost("sso.acme.com")

	if c.inScopeURL("https://sso.acme.com/login") {
		t.Error("a denied wall host must be out of scope even though CrawlScope admits it")
	}
	if c.inScopeURL("https://sso.acme.com/u/login/identifier?state=abc") {
		t.Error("denial must cover every path on the wall host, not just the landing path")
	}
	if !c.inScopeURL("https://app.acme.com/dashboard") {
		t.Error("denying the wall must not narrow the target itself")
	}
}

func TestIsTargetHost(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")

	tests := []struct {
		host string
		want bool
	}{
		{"app.acme.com", true},
		{"APP.ACME.COM", true},
		{"api.app.acme.com", true}, // subdomain of the target
		{"sso.acme.com", false},    // sibling host, same registrable domain
		{"acme.com", false},        // parent, not the target
		{"login.microsoftonline.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := c.isTargetHost(tt.host); got != tt.want {
			t.Errorf("isTargetHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}

	c.adoptedHost = "relocated.example.org"
	if !c.isTargetHost("relocated.example.org") {
		t.Error("an adopted relocation host counts as the target")
	}
}

// TestDenyRedirectChainWallsCoversEveryHop pins the fix for an SSO bounce that
// crosses two hosts: an authorize endpoint on one, the login form on another.
// Denying only the landing left the authorize host in scope, and the discovery
// phase went on to brute-force it.
func TestDenyRedirectChainWallsCoversEveryHop(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")
	c.observedLoginHosts = func() []string {
		return []string{
			"idp.acme.net", // the 307 authorize hop
			"sso.acme.com", // the login form the browser came to rest on
			"app.acme.com", // the target's own login page - must NOT be denied
		}
	}

	c.denyRedirectChainWalls()

	got := c.wallHostList()
	want := map[string]bool{"idp.acme.net": true, "sso.acme.com": true}
	if len(got) != len(want) {
		t.Fatalf("wallHostList() = %v, want the two off-target hops only", got)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected denied host %q", h)
		}
	}
	if c.isWallHost("app.acme.com") {
		t.Error("the target's own login page must never be denied as a wall")
	}
}

func TestDenyRedirectChainWallsNoHookIsSafe(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")
	c.observedLoginHosts = nil
	c.denyRedirectChainWalls() // must not panic
	if got := c.wallHostList(); len(got) != 0 {
		t.Errorf("wallHostList() = %v, want empty when no chain information is available", got)
	}
}

// TestStartWalledTerminatesCrawl pins that denying the wall also STOPS the
// crawl. Denial alone left the main loop resetting to the start URL, being
// redirected to the same wall, and going out of scope again — an oscillation
// that ran out the whole time budget and re-entered the OAuth flow on every lap.
func TestStartWalledTerminatesCrawl(t *testing.T) {
	c := newLoginTestCrawler(t, "https://app.acme.com")
	ctx := context.Background()

	if c.shouldTerminate(ctx) {
		t.Fatal("a fresh crawler should not terminate")
	}

	c.startWalled.Store(true)

	if !c.shouldTerminate(ctx) {
		t.Error("a start URL walled behind an off-host login must terminate the crawl")
	}
}
