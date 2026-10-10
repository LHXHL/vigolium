package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// The dynamic-assessment phase installs the configured spidering.stealth as
// the module browser confirmations' default, next to the scan's proxy.
func TestProbeStealthFollowsSettings(t *testing.T) {
	r := &Runner{}
	if got := r.probeStealth(); got != "" {
		t.Fatalf("no settings: probeStealth = %q, want auto (\"\")", got)
	}
	settings := config.DefaultSettings()
	settings.Spidering.Stealth = "off"
	r.settings = settings
	if got := r.probeStealth(); got != "off" {
		t.Fatalf("probeStealth = %q, want the configured off", got)
	}

	restore := spitolas.SetProbeDefaults("http://127.0.0.1:8081", r.probeStealth())
	if spitolas.DefaultProbeStealth() != "off" || spitolas.DefaultProbeProxy() != "http://127.0.0.1:8081" {
		t.Fatalf("defaults = %q / %q", spitolas.DefaultProbeStealth(), spitolas.DefaultProbeProxy())
	}
	restore()
	if spitolas.DefaultProbeStealth() != "" || spitolas.DefaultProbeProxy() != "" {
		t.Fatalf("restore left %q / %q", spitolas.DefaultProbeStealth(), spitolas.DefaultProbeProxy())
	}
}
