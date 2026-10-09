package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/harvester"
)

// ExternalHarvesterConfig holds configuration for pre-scan external intelligence harvesting.
type ExternalHarvesterConfig struct {
	Sources []string                 `yaml:"sources"`
	APIKeys ExternalHarvesterAPIKeys `yaml:"api_keys"`

	// PerShape caps how many URLs are kept per path shape (host + templated
	// path + sorted query names), so /item/1 … /item/90000 collapse to a few
	// samples. 0 uses the built-in default; a negative value disables the cap.
	PerShape int `yaml:"per_shape"`

	// MaxURLs caps the URLs kept per harvested domain after shaping. 0 uses the
	// built-in default; a negative value disables the cap.
	MaxURLs int `yaml:"max_urls"`

	// CDX bounds the Wayback Machine CDX index query.
	CDX ExternalHarvesterCDXConfig `yaml:"cdx"`
}

// ExternalHarvesterCDXConfig bounds the paged Wayback CDX index query.
type ExternalHarvesterCDXConfig struct {
	// PageSize is the rows requested per resumeKey page. 0 uses the default.
	PageSize int `yaml:"page_size"`

	// MaxRows is the hard cap on index rows read per domain; hitting it is
	// reported as the cdx_max_rows phase limit. 0 uses the default; a negative
	// value disables the cap.
	MaxRows int `yaml:"max_rows"`
}

// ExternalHarvesterAPIKeys holds API keys for external harvester sources that require authentication.
type ExternalHarvesterAPIKeys struct {
	URLScan    string `yaml:"urlscan"`
	VirusTotal string `yaml:"virustotal"`
}

// DefaultExternalHarvesterConfig returns default external harvester configuration.
//
// Only keyless sources are enabled by default, so the phase runs the same way
// whether or not any credential is configured. urlscan and virustotal join in
// only when their key is set.
func DefaultExternalHarvesterConfig() *ExternalHarvesterConfig {
	return &ExternalHarvesterConfig{
		Sources:  []string{"wayback", "commoncrawl", "alienvault", "arquivo"},
		PerShape: harvester.DefaultPerShape,
		MaxURLs:  harvester.DefaultMaxURLs,
		CDX: ExternalHarvesterCDXConfig{
			PageSize: harvester.DefaultCDXPageSize,
			MaxRows:  harvester.DefaultCDXMaxRows,
		},
	}
}

var validExternalHarvesterSources = map[string]bool{
	"wayback":     true,
	"commoncrawl": true,
	"arquivo":     true,
	"urlscan":     true,
	"alienvault":  true,
	"virustotal":  true,
}

// keyedSources maps each source that cannot run without a credential to the
// config field supplying it. One table drives both the "is a key required" test
// and the "which key is missing" message, so a source cannot end up in one and
// not the other.
var keyedSources = map[string]struct {
	field string
	value func(ExternalHarvesterAPIKeys) string
}{
	"urlscan":    {"api_keys.urlscan", func(k ExternalHarvesterAPIKeys) string { return k.URLScan }},
	"virustotal": {"api_keys.virustotal", func(k ExternalHarvesterAPIKeys) string { return k.VirusTotal }},
}

// Validate checks external harvester configuration for errors.
func (c *ExternalHarvesterConfig) Validate() error {
	for _, s := range c.Sources {
		if !validExternalHarvesterSources[s] {
			// The list is derived rather than written out, so it cannot drift
			// from the map that actually decides.
			valid := slices.Sorted(maps.Keys(validExternalHarvesterSources))
			return fmt.Errorf("external_harvester.sources: unknown source %q (valid: %s)",
				s, strings.Join(valid, ", "))
		}

		if keyed, ok := keyedSources[s]; ok && keyed.value(c.APIKeys) == "" {
			return fmt.Errorf("external_harvester: source %q requires %s to be set", s, keyed.field)
		}
	}

	if c.CDX.PageSize < 0 {
		return fmt.Errorf("external_harvester.cdx.page_size: must be >= 0, got %d", c.CDX.PageSize)
	}

	return nil
}

// HarvesterOptions converts the shaping and CDX bounds into the harvester's
// options. The zero/negative convention is shared, so values pass through.
func (c *ExternalHarvesterConfig) HarvesterOptions() harvester.Options {
	return harvester.Options{
		PerShape:    c.PerShape,
		MaxURLs:     c.MaxURLs,
		CDXPageSize: c.CDX.PageSize,
		CDXMaxRows:  c.CDX.MaxRows,
	}
}
