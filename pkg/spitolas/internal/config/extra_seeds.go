package config

// DefaultMaxExtraSeeds bounds how many caller-supplied seeds one crawl browses
// when Config.MaxExtraSeeds is unset. Each costs a navigation and a settle.
const DefaultMaxExtraSeeds = 50

// Extra seed navigation modes. A history route is a path on the target's
// origin; a hash route lives in the fragment of the start page. Auto (empty)
// picks hash when the seed itself carries a fragment route or the landing page
// is hash-routed, else history.
const (
	SeedModeAuto    = ""
	SeedModeHistory = "history"
	SeedModeHash    = "hash"
)

// ExtraSeed is one caller-supplied crawl entry point. URL is an absolute URL
// or a route relative to the start URL ("/users/:id", "#/users/:id"); route
// parameters are substituted before navigation. Higher Priority is browsed
// first. Source names where the seed came from, for logs.
type ExtraSeed struct {
	URL      string
	Source   string
	Priority int
	Mode     string
}

// ExtraSeedCap is MaxExtraSeeds with the default applied.
func (c *Config) ExtraSeedCap() int {
	if c.MaxExtraSeeds > 0 {
		return c.MaxExtraSeeds
	}
	return DefaultMaxExtraSeeds
}
