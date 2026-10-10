package crawler

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// isInScope checks if the current page URL is within the crawl scope.
// Returns true if in scope, false if out of scope.
func (c *Crawler) isInScope(page *browser.Page) bool {
	currentURL, err := page.URL()
	if err != nil {
		return false // Can't determine, assume out of scope
	}
	return c.inScopeURL(currentURL)
}

// inScopeURL is the scope decision itself, separated from reading the URL out
// of a live page so it can be exercised without a browser.
func (c *Crawler) inScopeURL(currentURL string) bool {
	// Parsed once and shared by both branches. The wall check used to add a parse
	// of its own on top of the default branch's two (this URL, then a needless
	// re-parse of c.config.URL, which is already a *url.URL).
	u, err := url.Parse(currentURL)
	if err != nil {
		return false // Can't determine, assume out of scope
	}

	// A denied login/SSO wall is out of scope ahead of every other rule,
	// including an explicit operator CrawlScope. See wallHosts.
	if c.isWallHost(u.Hostname()) {
		return false
	}

	if c.config.CrawlScope != nil {
		return c.config.CrawlScope(currentURL)
	}

	// Default: the target host, its subdomains, or an adopted relocation host.
	return c.isTargetHost(u.Hostname())
}

// denyRedirectChainWalls denies every off-target host observed serving an
// authentication endpoint, so an SSO bounce is excluded end to end rather than
// only at the host the browser came to rest on.
//
// The target's own hosts are never denied: a login page on the application
// under test is a legitimate crawl and scan surface. Only somebody else's
// identity provider is excluded, and only once the landing has already been
// classified as a wall — so an ordinary app that happens to serve /login on a
// sibling host is untouched.
func (c *Crawler) denyRedirectChainWalls() {
	if c.observedLoginHosts == nil {
		return
	}
	for _, host := range c.observedLoginHosts() {
		if c.isTargetHost(host) {
			continue
		}
		c.denyWallHost(host)
	}
}

// isTargetHost reports whether host belongs to the target under test (the
// configured target host, one of its subdomains, or an adopted relocation
// host) — the hosts a wall denial must never remove from scope.
func (c *Crawler) isTargetHost(host string) bool {
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if c.config != nil && c.config.URL != nil {
		if sameOrSubdomain(host, strings.ToLower(c.config.URL.Hostname())) {
			return true
		}
	}
	return c.adoptedHost != "" && sameOrSubdomain(host, c.adoptedHost)
}

// denyWallHost marks host as a login/SSO wall, putting it out of scope for the
// rest of the crawl. Idempotent and safe for concurrent use.
func (c *Crawler) denyWallHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	c.wallHostsMu.Lock()
	defer c.wallHostsMu.Unlock()
	// Lazily allocated despite New initializing it: a Crawler is also built by
	// struct literal in tests, and a nil-map write here would panic rather than
	// fail.
	if c.wallHosts == nil {
		c.wallHosts = make(map[string]bool)
	}
	if c.wallHosts[host] {
		return
	}
	c.wallHosts[host] = true
	c.hasWallHosts.Store(true)
	zap.L().Info("Spidering: login/SSO wall host denied for the rest of the crawl",
		zap.String("host", host))
}

// isWallHost reports whether host has been denied as a login/SSO wall.
//
// The hasWallHosts gate keeps the common case free: a crawl that never hits a
// wall — nearly all of them — answers with one atomic load and never takes the
// lock, and this runs on the per-navigation scope path. Mirrors the hasDynamic
// gate ScopeMatcher.hostInScope uses for the same reason.
func (c *Crawler) isWallHost(host string) bool {
	if !c.hasWallHosts.Load() || host == "" {
		return false
	}
	c.wallHostsMu.RLock()
	defer c.wallHostsMu.RUnlock()
	return c.wallHosts[strings.ToLower(host)]
}

// wallHostList returns the denied wall hosts, sorted for stable reporting.
func (c *Crawler) wallHostList() []string {
	c.wallHostsMu.RLock()
	defer c.wallHostsMu.RUnlock()
	if len(c.wallHosts) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(c.wallHosts))
}

// sameOrSubdomain reports whether host equals base or is a subdomain of it.
func sameOrSubdomain(host, base string) bool {
	if host == "" || base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

// evaluateStartRedirect inspects the index (start) page after the browser has
// followed any initial redirects. When the start URL bounced to a different
// host (a common SSO/login pattern), the default same-host scope would trap the
// crawler on the landing page and yield almost nothing. If that landing is NOT
// a login/SSO wall, we adopt its host into scope so the crawl can proceed
// against the relocated app; login walls are left out of scope (nothing useful
// to crawl unauthenticated) but recorded so the caller can advise on auth.
//
// Only applies under the default host-scope rule — an explicit CrawlScope is
// the operator's own boundary and is never widened here.
func (c *Crawler) evaluateStartRedirect(page *browser.Page, landingURL string) {
	if landingURL == "" {
		return
	}

	landing, err := url.Parse(landingURL)
	if err != nil {
		return
	}
	landHost := strings.ToLower(landing.Hostname())
	tgtHost := strings.ToLower(c.config.URL.Hostname())
	if landHost == "" || tgtHost == "" || sameOrSubdomain(landHost, tgtHost) {
		return // no off-host redirect
	}

	c.stats.OffHostLanding = true
	c.stats.LandingURL = landingURL

	// Whatever the landing turns out to be, the operator's credential headers
	// stop here unless the operator scope admits the new host.
	c.withdrawCredentialHeaders(page, landingURL, landHost)

	// Login/SSO-wall detection runs regardless of scope mode so the caller still
	// gets the "supply --auth" advice and the SSO host is excluded from fuzzing —
	// even under an explicit operator scope.
	if c.landingLooksLikeLogin(page, landing) {
		c.stats.LandingIsLogin = true
		// Deny the wall itself and every authentication hop the browser passed
		// through on the way here. Denial (not just classification) is what stops
		// the crawl: without it the configured scope rule usually still admits
		// these hosts and the crawler spends its budget on the IdP.
		c.denyWallHost(landHost)
		c.denyRedirectChainWalls()
		c.stats.WallHosts = c.wallHostList()
		c.startWalled.Store(true)
		zap.L().Warn("Spidering: start URL redirected to an off-host login wall — stopping the crawl",
			zap.String("target", c.config.URL.String()),
			zap.String("landing", landingURL),
			zap.Strings("denied_hosts", c.stats.WallHosts))
		return
	}

	// Non-login off-host landing: adopt it so the crawl can continue — but ONLY
	// under the default host-scope rule. An explicit CrawlScope is the operator's
	// own boundary and is never widened; if the relocated host is genuinely in
	// scope the CrawlScope filter already admits it, so no adoption is needed.
	if c.config.CrawlScope != nil {
		return
	}
	c.adoptedHost = landHost
	c.stats.HostAdopted = true
	zap.L().Info("Spidering: adopting off-host redirect target into scope",
		zap.String("target", c.config.URL.String()),
		zap.String("landing", landingURL),
		zap.String("adopted_host", landHost))
}

// landingLooksLikeLogin classifies an off-host start-redirect landing as a
// login/SSO wall. A URL that matches a known identity-provider host or a
// login/authorize path is treated as a wall outright; otherwise a visible
// password field on the rendered page is the strongest remaining signal.
func (c *Crawler) landingLooksLikeLogin(page *browser.Page, landing *url.URL) bool {
	if looksLikeLoginURL(landing) {
		return true
	}
	if page == nil {
		return false
	}
	// A visible password field is the strongest remaining login signal. Eval
	// runs a JS expression and returns the value by-value; treat any error or
	// non-true result as "not a login page" so a flaky probe never blocks a
	// crawl we'd otherwise proceed with.
	val, err := page.Eval(`(function(){return !!document.querySelector('input[type=password]')})()`)
	if err != nil {
		return false
	}
	hasPassword, _ := val.(bool)
	return hasPassword
}

// looksLikeLoginURL reports whether u points at an authentication endpoint,
// based on its host and path/query alone (no page load required). The
// signature tables live in pkg/authsig so other phases (e.g. the
// targeted re-spider candidate screen) share one source of truth.
func looksLikeLoginURL(u *url.URL) bool {
	return authsig.LooksLikeLoginURL(u)
}

// visitAnchorHref navigates directly to an anchor's href URL.
// Used when crawlHiddenAnchors is enabled and clicking a hidden anchor fails.
func (c *Crawler) visitAnchorHref(page *browser.Page, href string) error {
	// Resolve relative URL against current page URL
	currentURL, err := page.URL()
	if err != nil {
		return fmt.Errorf("failed to get current URL: %w", err)
	}

	// Parse and resolve the href
	baseURL, err := url.Parse(currentURL)
	if err != nil {
		return fmt.Errorf("failed to parse current URL: %w", err)
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return fmt.Errorf("failed to parse href: %w", err)
	}

	// Resolve relative URL
	resolvedURL := baseURL.ResolveReference(hrefURL)

	zap.L().Debug("Navigating to anchor href", zap.String("url", resolvedURL.String()))
	return page.Navigate(resolvedURL.String())
}

// shouldCrawl checks if page should be crawled based on conditions.
func (c *Crawler) shouldCrawl(page *browser.Page) bool {
	if len(c.crawlConditions) == 0 {
		return true
	}

	for _, cond := range c.crawlConditions {
		if !cond.Check(page) {
			return false
		}
	}

	return true
}
