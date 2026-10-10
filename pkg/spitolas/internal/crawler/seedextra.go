package crawler

import (
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle/clientroute"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"go.uber.org/zap"
)

// ResolveExtraSeed turns one caller-supplied seed into the URL the browser
// navigates to. start is the crawl's start URL; hashApp says the landing page
// is hash-routed (its fragment carries a route), which is what an auto-mode
// seed follows.
//
// The navigation rule:
//   - a history route is origin + path ("/users/:id" → https://app/users/1);
//   - a hash route is the start page + "#" + route (→ https://app/#/users/1),
//     keeping a "#!" hashbang when the seed has one;
//   - route parameters are substituted the way discovery does
//     (clientroute.Stable), and a route that cannot be made concrete
//     (wildcards, unresolved templates) is refused.
func ResolveExtraSeed(start *url.URL, seed config.ExtraSeed, hashApp bool) (string, bool) {
	raw := strings.TrimSpace(seed.URL)
	if raw == "" || start == nil {
		return "", false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	base := *start
	base.Fragment, base.RawFragment = "", ""
	u := base.ResolveReference(ref)
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", false
	}

	// A seed that already names a fragment route is a hash route on its own
	// page, whatever the mode says.
	if prefix, route, ok := clientroute.HashRoute(u.Fragment); ok {
		stable, ok := clientroute.Stable(route)
		if !ok {
			return "", false
		}
		page := *u
		page.Fragment, page.RawFragment = prefix+stable, ""
		return page.String(), true
	}

	stable, ok := clientroute.Stable(u.Path)
	if !ok {
		return "", false
	}
	hash := seed.Mode == config.SeedModeHash || seed.Mode == config.SeedModeAuto && hashApp
	if !hash {
		out := *u
		out.Path, out.RawPath = stable, ""
		out.Fragment, out.RawFragment = "", ""
		return out.String(), true
	}
	// Hash route: the start page when the seed is on the start origin, else
	// the root of the seed's own origin.
	page := base
	if !strings.EqualFold(u.Host, base.Host) || u.Scheme != base.Scheme {
		page = url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
	}
	if page.Path == "" {
		page.Path = "/"
	}
	page.Fragment = stable
	return page.String(), true
}

// extraSeedKey is the dedup key of a resolved seed: origin, the path's shape
// (identifier segments collapsed, as for sitemap seeds) and, for a hash route,
// the route's shape. /users/1 and /users/2 are one seed; #/a and #/b are two.
func extraSeedKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	key := strings.ToLower(u.Scheme + "://" + u.Host + seedPathShape(u.Path))
	if prefix, route, ok := clientroute.HashRoute(u.Fragment); ok {
		key += "#" + prefix + seedPathShape(route)
	}
	return key
}

// isHashRouted reports whether a page URL carries a client route in its
// fragment ("/#/dashboard", "/#!/home").
func isHashRouted(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	_, _, ok := clientroute.HashRoute(u.Fragment)
	return ok
}

// selectExtraSeeds resolves, scope-filters and dedups the configured extra
// seeds against the locations already chosen (declared) and the landing page,
// then keeps the highest-priority ones up to the cap. inScope is the crawl's
// scope decision; landing is the page the crawl settled on.
func selectExtraSeeds(seeds []config.ExtraSeed, start *url.URL, landing string, declared []string, limit int, inScope func(string) bool) []string {
	if len(seeds) == 0 || limit <= 0 {
		return nil
	}
	hashApp := isHashRouted(landing) || (start != nil && isHashRouted(start.String()))

	seen := make(map[string]struct{}, len(declared)+2)
	if landing != "" {
		seen[extraSeedKey(landing)] = struct{}{}
	}
	if start != nil {
		seen[extraSeedKey(start.String())] = struct{}{}
	}
	for _, d := range declared {
		seen[extraSeedKey(d)] = struct{}{}
	}

	ordered := make([]config.ExtraSeed, len(seeds))
	copy(ordered, seeds)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority > ordered[j].Priority })

	out := make([]string, 0, min(limit, len(ordered)))
	for _, seed := range ordered {
		if len(out) >= limit {
			break
		}
		resolved, ok := ResolveExtraSeed(start, seed, hashApp)
		if !ok || (inScope != nil && !inScope(resolved)) {
			continue
		}
		key := extraSeedKey(resolved)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

// extraSeedURLs is selectExtraSeeds for this crawl: its configured seeds,
// start URL, scope and the page it is on.
func (c *Crawler) extraSeedURLs(page *browser.Page, declared []string) []string {
	if c.config == nil || len(c.config.ExtraSeeds) == 0 {
		return nil
	}
	landing := ""
	if page != nil {
		landing, _ = page.URL()
	}
	out := selectExtraSeeds(c.config.ExtraSeeds, c.config.URL, landing, declared, c.config.ExtraSeedCap(), c.inScopeURL)
	c.mu.Lock()
	c.stats.ExtraSeedsAccepted = len(out)
	c.mu.Unlock()
	if len(out) > 0 {
		zap.L().Info("Frontier seeded with caller-supplied routes",
			zap.Int("configured", len(c.config.ExtraSeeds)), zap.Int("accepted", len(out)))
	}
	return out
}
