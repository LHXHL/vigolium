package cli

import (
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// installDirectProbeDefaults makes the scan's --proxy and the configured
// spidering.stealth the defaults for module browser confirmations (XSS dialog
// probes) on the direct scan-url / scan-request path, as the runner does for
// its dynamic-assessment phase; without them a confirmation went around
// --proxy and ignored stealth. The returned func restores the previous
// defaults.
func installDirectProbeDefaults() (restore func()) {
	stealth := ""
	// The direct path loads no settings of its own; an unreadable config
	// keeps the auto default rather than failing a scan over a browser knob.
	if settings, err := loadProjectSettings(globalConfig); err == nil && settings != nil {
		stealth = settings.Spidering.Stealth
	}
	return spitolas.SetProbeDefaults(globalProxy, stealth)
}
