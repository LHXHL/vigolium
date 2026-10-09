package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestBuildDeparosConfigCarriesSitemap pins the YAML → source mapping for
// discovery.sitemap.
func TestBuildDeparosConfigCarriesSitemap(t *testing.T) {
	settings := paceSettings(nil)
	off := false
	settings.Discovery.Sitemap.Enabled = &off
	settings.Discovery.Sitemap.MaxURLs = 50
	r := &Runner{options: &types.Options{Targets: []string{"https://example.com"}, Concurrency: 25}, settings: settings}

	got := r.buildDeparosConfig(nil).Sitemap
	if got == nil || got.Enabled || got.MaxURLs != 50 || !got.FollowIndex {
		t.Fatalf("Sitemap = %+v, want disabled, max_urls 50, follow_index on", got)
	}

	defaults := (&Runner{options: &types.Options{Targets: []string{"https://example.com"}}, settings: paceSettings(nil)}).
		buildDeparosConfig(nil).Sitemap
	if defaults == nil || !defaults.Enabled || defaults.MaxURLs != 2000 || defaults.PerShape != 3 || !defaults.FollowIndex {
		t.Fatalf("default Sitemap = %+v, want enabled, 2000, 3, follow_index", defaults)
	}
}

// TestReportDiscoveryCoverageNotesSitemapCap: a capped sitemap is a limit on
// the phase outcome, not a silent drop.
func TestReportDiscoveryCoverageNotesSitemapCap(t *testing.T) {
	r := &Runner{options: &types.Options{Silent: true}}
	tracker := &phaseTracker{}
	r.currentPhase.Store(tracker)
	r.reportDiscoveryCoverage(source.DiscoveryStats{SitemapCapped: 7})
	if _, found := tracker.limits[database.LimitSitemapCap]; !found {
		t.Fatalf("limits = %v, want %s", tracker.limits, database.LimitSitemapCap)
	}
}
