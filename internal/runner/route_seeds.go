package runner

import (
	"context"
	neturl "net/url"
	"sort"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/clientroute"
	"github.com/vigolium/vigolium/pkg/deparos/tag"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"go.uber.org/zap"
)

// Client routes as browser seeds. Discovery stores every route the target's
// JavaScript declares (jstangle-facts artifacts); a route nothing links to is
// otherwise invisible to an interaction crawl. Two consumers:
//   - the initial spidering phase passes routes earlier runs of the project
//     stored as SpiderConfig.ExtraSeeds (`run spidering` after `run discovery`);
//   - the targeted re-spider takes this scan's routes as candidates beside the
//     record-derived ones, under the same caps and route dedup.
//
// Both are gated by spidering.route_seeds.

// routeSeedSource labels seeds that come from client routes.
const routeSeedSource = "jstangle-route"

// routeSeedReadCap bounds how many stored routes one phase reads.
const routeSeedReadCap = 5000

// routeSeedPath is the concrete path a stored client route navigates to, or
// false when it is no browser target: a redirect, a low-confidence guess, an
// API route, or a nested route whose parent lives in another module (its
// fullPath is a template, so there is no concrete prefix to navigate).
func routeSeedPath(cr database.ClientRoute) (string, bool) {
	if clientroute.Skip(cr.RouteType, cr.Confidence) || cr.RouteType == "api" {
		return "", false
	}
	if cr.FullPath != "" && !cr.FullPathStatic {
		return "", false
	}
	return clientroute.SeedPath(cr.Path, cr.FullPath, cr.Extractor)
}

// routeSeedURL is the URL the browser navigates to for a stored route: its
// anchor record's origin plus the concrete route path (history routing, the
// shared spitolas navigation rule).
func routeSeedURL(cr database.ClientRoute) (*neturl.URL, bool) {
	path, ok := routeSeedPath(cr)
	if !ok {
		return nil, false
	}
	origin := buildOriginURL(cr.Scheme, cr.Hostname, cr.Port) + "/"
	resolved, ok := spitolas.ResolveSeedURL(origin, spitolas.SeedURL{URL: path, Mode: spitolas.SeedModeHistory}, false)
	if !ok {
		return nil, false
	}
	u, err := neturl.Parse(resolved)
	if err != nil || u.Host == "" {
		return nil, false
	}
	return u, true
}

// evaluateRouteSeed is the re-spider verdict for a client-route seed. A route
// has no stored response, so the body gates do not apply; what still does is
// the path shape and the login screen.
func evaluateRouteSeed(u *neturl.URL) respiderVerdict {
	if !tag.IsValidModernAppPath(u.Path) {
		return respiderVerdict{Reason: "bad-path"}
	}
	if authsig.LooksLikeLoginURL(u) {
		return respiderVerdict{Reason: "login"}
	}
	return respiderVerdict{Keep: true, Reason: routeSeedSource, Score: scoreCandidate(u, routeSeedSource)}
}

// routeEvaluated turns stored client routes into re-spider candidates.
// Unusable routes are dropped here rather than tallied: they were never
// navigation targets.
func routeEvaluated(routes []database.ClientRoute) []respiderEvaluated {
	out := make([]respiderEvaluated, 0, len(routes))
	for _, cr := range routes {
		u, ok := routeSeedURL(cr)
		if !ok {
			continue
		}
		out = append(out, respiderEvaluated{
			source:   routeSeedSource,
			hostname: cr.Hostname,
			url:      u.String(),
			decodeOK: true,
			verdict:  evaluateRouteSeed(u),
		})
	}
	return out
}

// collectReSpiderRoutes reads the client routes this scan's discovery stored
// for the in-scope origins and turns them into re-spider candidates.
func (r *Runner) collectReSpiderRoutes(ctx context.Context, scanUUID string) []respiderEvaluated {
	if r.repository == nil || r.settings == nil || !r.settings.Spidering.RouteSeedsEnabled() || scanUUID == "" {
		return nil
	}
	hosts := r.getInScopeDBHosts(ctx)
	if len(hosts) == 0 {
		return nil
	}
	routes, err := r.repository.ListClientRoutes(ctx, scanUUID, r.options.ProjectUUID, hosts, routeSeedReadCap)
	if err != nil {
		zap.L().Warn("Re-spider: failed to read client routes", zap.Error(err))
		return nil
	}
	return routeEvaluated(routes)
}

// routeSeedSet is the initial crawl's client-route seeds, by hostname.
type routeSeedSet struct {
	byHost map[string][]spitolas.SeedURL
	total  int
}

// forTarget returns the seeds for target's host. A shared host session
// browses them once (SpiderSession), so handing them to every target of the
// host costs nothing extra there.
func (s *routeSeedSet) forTarget(target string) []spitolas.SeedURL {
	if s == nil || target == "" {
		return nil
	}
	return s.byHost[httpmsg.HostnameFromURL(target)]
}

// count is the number of seeds carried across all hosts.
func (s *routeSeedSet) count() int {
	if s == nil {
		return 0
	}
	return s.total
}

// newRouteSeedSet groups stored routes into per-host seeds, best-ranked first
// and at most perHost each (the crawler applies the same cap after its own
// scope filter and dedup; this only bounds what is carried).
func newRouteSeedSet(routes []database.ClientRoute, perHost int) *routeSeedSet {
	set := &routeSeedSet{byHost: make(map[string][]spitolas.SeedURL)}
	seen := make(map[string]struct{})
	for _, cr := range routes {
		u, ok := routeSeedURL(cr)
		if !ok {
			continue
		}
		v := evaluateRouteSeed(u)
		if !v.Keep {
			continue
		}
		key := canonicalRoute(u)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		host := cr.Hostname
		set.byHost[host] = append(set.byHost[host], spitolas.SeedURL{
			URL: u.String(), Source: routeSeedSource, Priority: v.Score,
		})
	}
	for host, seeds := range set.byHost {
		sort.SliceStable(seeds, func(i, j int) bool { return seeds[i].Priority > seeds[j].Priority })
		if perHost > 0 && len(seeds) > perHost {
			seeds = seeds[:perHost]
		}
		set.byHost[host] = seeds
		set.total += len(seeds)
	}
	if set.total == 0 {
		return nil
	}
	return set
}

// loadSpiderRouteSeeds reads the client routes earlier runs of this project
// stored for the in-scope origins, for the initial crawl. Nil when disabled,
// when the database knows no in-scope origin, or when there are none.
func (r *Runner) loadSpiderRouteSeeds(ctx context.Context) *routeSeedSet {
	if r.repository == nil || r.settings == nil || !r.settings.Spidering.RouteSeedsEnabled() {
		return nil
	}
	hosts := r.getInScopeDBHosts(ctx)
	if len(hosts) == 0 {
		return nil
	}
	routes, err := r.repository.ListClientRoutes(ctx, "", r.options.ProjectUUID, hosts, routeSeedReadCap)
	if err != nil {
		zap.L().Warn("Spidering: failed to read stored client routes", zap.Error(err))
		return nil
	}
	return newRouteSeedSet(routes, r.settings.Spidering.ExtraSeedsCap())
}
