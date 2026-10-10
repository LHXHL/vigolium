package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestBuildDeparosConfigCarriesJSTemplatePersistence pins the YAML →
// source mapping for discovery.jstangle.persist_*.
func TestBuildDeparosConfigCarriesJSTemplatePersistence(t *testing.T) {
	settings := paceSettings(nil)
	off := false
	settings.Discovery.JSTangle.PersistUnreplayed = &off
	settings.Discovery.JSTangle.PersistNotFoundEmitStatuses = []int{422}
	settings.Discovery.JSTangle.MaxPersistedJSTemplates = 50
	r := &Runner{options: &types.Options{Targets: []string{"https://example.com"}, Concurrency: 25}, settings: settings}

	got := r.buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).JSTemplatePersist
	want := source.JSTemplatePersistConfig{SkipUnreplayed: true, EmitStatuses: []int{422}, MaxPerTarget: 50}
	if got.SkipUnreplayed != want.SkipUnreplayed || got.MaxPerTarget != want.MaxPerTarget ||
		len(got.EmitStatuses) != 1 || got.EmitStatuses[0] != 422 {
		t.Fatalf("JSTemplatePersist = %+v, want %+v", got, want)
	}

	defaults := (&Runner{options: &types.Options{Targets: []string{"https://example.com"}}, settings: paceSettings(nil)}).
		buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).JSTemplatePersist
	if defaults.SkipUnreplayed || defaults.EmitStatuses != nil || defaults.MaxPerTarget != 2000 {
		t.Fatalf("default JSTemplatePersist = %+v, want persist on, default emit list, cap 2000", defaults)
	}
}

// TestReportDiscoveryCoverageNotesJSTemplateCap: a capped target is a limit on
// the phase outcome, not a silent drop.
func TestReportDiscoveryCoverageNotesJSTemplateCap(t *testing.T) {
	r := &Runner{options: &types.Options{Silent: true}}
	tracker := &phaseTracker{}
	r.currentPhase.Store(tracker)
	r.reportDiscoveryCoverage(source.DiscoveryStats{JSTemplatesCapped: 3})
	if _, found := tracker.limits[database.LimitJSTemplatePersistCap]; !found {
		t.Fatalf("limits = %v, want %s", tracker.limits, database.LimitJSTemplatePersistCap)
	}
}
