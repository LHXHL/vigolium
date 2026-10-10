package spitolas

import (
	"context"
	"slices"
	"strings"
	"testing"

	appconfig "github.com/vigolium/vigolium/internal/config"
)

// spidering.stealth is validated in internal/config, which cannot import this
// package; the two lists must not drift.
func TestStealthModesMatchSpideringConfig(t *testing.T) {
	if !slices.Equal(StealthModes, appconfig.SpideringStealthModes) {
		t.Errorf("spitolas.StealthModes = %v, config.SpideringStealthModes = %v", StealthModes, appconfig.SpideringStealthModes)
	}
	if def := appconfig.DefaultSpideringConfig().Stealth; def != StealthModes[0] {
		t.Errorf("default spidering.stealth = %q, want %q", def, StealthModes[0])
	}
}

// spidering.tabs / tab_isolation are validated in internal/config too.
func TestTabSettingsMatchSpideringConfig(t *testing.T) {
	if !slices.Equal(TabIsolationModes, appconfig.SpideringTabIsolationModes) {
		t.Errorf("spitolas.TabIsolationModes = %v, config.SpideringTabIsolationModes = %v", TabIsolationModes, appconfig.SpideringTabIsolationModes)
	}
	if MaxTabs != appconfig.SpideringMaxTabs {
		t.Errorf("spitolas.MaxTabs = %d, config.SpideringMaxTabs = %d", MaxTabs, appconfig.SpideringMaxTabs)
	}
	def := appconfig.DefaultSpideringConfig()
	if def.Tabs != 1 {
		t.Errorf("default spidering.tabs = %d, want 1 until a multi-tab soak passes", def.Tabs)
	}
	if def.TabIsolation != TabIsolationModes[0] {
		t.Errorf("default spidering.tab_isolation = %q, want %q", def.TabIsolation, TabIsolationModes[0])
	}
}

// An unknown mode fails before any browser is launched.
func TestProbeURLRejectsUnknownStealth(t *testing.T) {
	_, err := ProbeURL(context.Background(), ProbeConfig{URL: "http://127.0.0.1:1/", Stealth: "max"})
	if err == nil || !strings.Contains(err.Error(), "Stealth must be one of") {
		t.Fatalf("err = %v, want a stealth validation error", err)
	}
}
