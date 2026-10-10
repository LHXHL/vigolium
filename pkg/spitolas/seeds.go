package spitolas

import (
	"net/url"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/crawler"
)

// Seed navigation modes for SeedURL.Mode. History routes are paths on the
// target's origin; hash routes live in the start page's fragment. Auto (the
// empty mode) is hash when the seed carries a fragment route or the landing
// page is hash-routed, else history.
const (
	SeedModeAuto    = config.SeedModeAuto
	SeedModeHistory = config.SeedModeHistory
	SeedModeHash    = config.SeedModeHash
)

// DefaultMaxExtraSeeds is the per-crawl cap on SpiderConfig.ExtraSeeds when
// MaxExtraSeeds is unset.
const DefaultMaxExtraSeeds = config.DefaultMaxExtraSeeds

// SeedURL is a caller-supplied crawl entry point the browser navigates to
// after the robots/sitemap seeds — typically a client-side route found in the
// target's JavaScript that nothing on the page links to.
//
// URL is an absolute URL or a route relative to the crawl's start URL
// ("/users/:id", "#/users/:id"). Route parameters (":id", "[id]", "{id}") are
// substituted with a placeholder value, and a route that cannot be made
// concrete is dropped. Seeds are scope-filtered, deduplicated by route shape
// and taken highest Priority first. Source labels the seed's origin in logs
// (for example "jstangle-route").
type SeedURL struct {
	URL      string
	Source   string
	Priority int
	Mode     string
}

// ResolveSeedURL is the URL a crawl starting at start navigates to for seed,
// applying the same rule as ExtraSeeds (history: origin + path; hash:
// start#route; parameters substituted). hashApp says the start page is
// hash-routed, which auto-mode seeds follow. ok is false for a seed that
// cannot be made concrete.
func ResolveSeedURL(start string, seed SeedURL, hashApp bool) (string, bool) {
	u, err := url.Parse(start)
	if err != nil {
		return "", false
	}
	return crawler.ResolveExtraSeed(u, seed.internal(), hashApp)
}

func (s SeedURL) internal() config.ExtraSeed {
	return config.ExtraSeed{URL: s.URL, Source: s.Source, Priority: s.Priority, Mode: s.Mode}
}

func extraSeedsToInternal(seeds []SeedURL) []config.ExtraSeed {
	if len(seeds) == 0 {
		return nil
	}
	out := make([]config.ExtraSeed, len(seeds))
	for i, s := range seeds {
		out[i] = s.internal()
	}
	return out
}
