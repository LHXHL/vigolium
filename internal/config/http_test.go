package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDefaultScanningStrategy_HTTPUserAgentPreset(t *testing.T) {
	cfg := DefaultScanningStrategyConfig()
	if cfg.HTTP.UserAgent != httpmsg.UserAgentPreset {
		t.Fatalf("default scanning_strategy.http.user_agent should be %q, got %q", httpmsg.UserAgentPreset, cfg.HTTP.UserAgent)
	}
}

// LoadSettings must read the nested scanning_strategy.http.user_agent key and
// install it as the process-global User-Agent (with {version} expansion).
func TestLoadSettings_NestedUserAgentWired(t *testing.T) {
	// A VIGOLIUM_DEFAULT_UA set in the invoking shell would override the
	// config-wired selector; clear it (t.Setenv registers the restore).
	t.Setenv(httpmsg.DefaultUserAgentEnvVar, "")
	if err := os.Unsetenv(httpmsg.DefaultUserAgentEnvVar); err != nil {
		t.Fatalf("unset %s: %v", httpmsg.DefaultUserAgentEnvVar, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "vigolium-configs.yaml")
	yaml := "scanning_strategy:\n" +
		"  default_strategy: balanced\n" +
		"  http:\n" +
		"    user_agent: \"Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	httpmsg.SetBuildVersion("v9.9.9")
	s, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}

	const want = "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
	if s.ScanningStrategy.HTTP.UserAgent != want {
		t.Fatalf("config value: got %q, want %q", s.ScanningStrategy.HTTP.UserAgent, want)
	}

	const resolved = "Mozilla/5.0 (compatible; Vigolium/v9.9.9; +https://github.com/vigolium/vigolium)"
	if got := httpmsg.DefaultUserAgent(); got != resolved {
		t.Fatalf("resolved UA: got %q, want %q", got, resolved)
	}
}

func TestHostErrorsConfig_DefaultsAndBreakerMapping(t *testing.T) {
	cfg := DefaultScanningStrategyConfig().HTTP.HostErrors
	bc := cfg.BreakerConfig()
	if bc.Cooldown != hosterrors.DefaultCooldown || bc.MaxCooldown != hosterrors.DefaultMaxCooldown || bc.MaxTrips != hosterrors.DefaultMaxTrips {
		t.Fatalf("default breaker config = %+v", bc)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	custom := HostErrorsConfig{Cooldown: "10s", MaxCooldown: "2m", MaxTrips: -1}
	bc = custom.BreakerConfig()
	if bc.Cooldown != 10*time.Second || bc.MaxCooldown != 2*time.Minute || bc.MaxTrips != -1 {
		t.Fatalf("custom breaker config = %+v", bc)
	}

	for _, bad := range []HostErrorsConfig{{Cooldown: "soon"}, {MaxCooldown: "-5m"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want error", bad)
		}
		s := DefaultScanningStrategyConfig()
		s.HTTP.HostErrors = bad
		if err := s.Validate(); err == nil {
			t.Errorf("ScanningStrategyConfig.Validate with %+v = nil, want error", bad)
		}
	}
}

func TestLoadSettings_HostErrorsSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vigolium-configs.yaml")
	yaml := "scanning_strategy:\n" +
		"  http:\n" +
		"    host_errors:\n" +
		"      cooldown: 45s\n" +
		"      max_trips: 2\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	s, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	got := s.ScanningStrategy.HTTP.HostErrors
	if got.Cooldown != "45s" || got.MaxTrips != 2 || got.MaxCooldown != hosterrors.DefaultMaxCooldown.String() {
		t.Fatalf("host_errors = %+v (unset keys should keep defaults)", got)
	}
}
