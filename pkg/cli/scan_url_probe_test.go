package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas"
)

// The direct scan-url / scan-request path installs --proxy and the configured
// spidering.stealth as the module browser confirmations' defaults, and
// restores them when the scan ends.
func TestInstallDirectProbeDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	if err := os.WriteFile(cfg, []byte("spidering:\n  stealth: \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prevConfig, prevProxy, prevStateless := globalConfig, globalProxy, globalStateless
	t.Cleanup(func() { globalConfig, globalProxy, globalStateless = prevConfig, prevProxy, prevStateless })
	globalConfig, globalProxy, globalStateless = cfg, "http://127.0.0.1:8089", true

	restore := installDirectProbeDefaults()
	if got := spitolas.DefaultProbeProxy(); got != "http://127.0.0.1:8089" {
		t.Errorf("probe proxy default = %q, want --proxy", got)
	}
	if got := spitolas.DefaultProbeStealth(); got != "off" {
		t.Errorf("probe stealth default = %q, want the configured off", got)
	}
	restore()
	if spitolas.DefaultProbeProxy() != "" || spitolas.DefaultProbeStealth() != "" {
		t.Errorf("restore left %q / %q", spitolas.DefaultProbeProxy(), spitolas.DefaultProbeStealth())
	}
}
