package config

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// HTTPConfig holds global outbound-HTTP settings applied across every scan
// phase (dynamic-assessment, discovery, fingerprinting, external harvesting).
// Nested under scanning_strategy; config path is scanning_strategy.http.*.
type HTTPConfig struct {
	// UserAgent selects the User-Agent header sent on every outgoing scanner
	// request (modules that deliberately inject their own User-Agent keep
	// theirs). Accepted values:
	//   "preset" — the self-identifying Vigolium string (the default):
	//     "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)".
	//     {version} is replaced with the running binary version.
	//   "random" — rotate a realistic browser string per request.
	//   ""       — blank behaves exactly like "random".
	//   <any>    — use the literal string verbatim ({version} still expands).
	// The VIGOLIUM_DEFAULT_UA env var overrides this when set, and an explicit
	// -H 'User-Agent: ...' flag still takes precedence for dynamic-assessment.
	UserAgent string `yaml:"user_agent"`

	// HostErrors tunes the dead-host breaker. The threshold that quarantines
	// a host stays --max-host-error (consecutive transport errors); these
	// settings decide how a quarantined host is re-probed and when it is
	// given up on. Config path: scanning_strategy.http.host_errors.*.
	HostErrors HostErrorsConfig `yaml:"host_errors"`
}

// HostErrorsConfig is the dead-host breaker's timing. A host:port that hits
// --max-host-error consecutive transport errors is quarantined for Cooldown;
// then one probe request is let through. A successful probe restores the host;
// a failed one doubles the cooldown (capped at MaxCooldown). After MaxTrips
// failed probes the host is dead for the rest of the scan.
type HostErrorsConfig struct {
	// Cooldown is the first quarantine period (Go duration, default 30s).
	Cooldown string `yaml:"cooldown"`
	// MaxCooldown caps the doubling cooldown (Go duration, default 5m).
	MaxCooldown string `yaml:"max_cooldown"`
	// MaxTrips is how many failed probes mark a host dead (default 5).
	// 0 means the default; a negative value never gives up on a host.
	MaxTrips int `yaml:"max_trips"`
}

// DefaultHostErrorsConfig returns the breaker defaults, owned by hosterrors.
func DefaultHostErrorsConfig() HostErrorsConfig {
	return HostErrorsConfig{
		Cooldown:    hosterrors.DefaultCooldown.String(),
		MaxCooldown: hosterrors.DefaultMaxCooldown.String(),
		MaxTrips:    hosterrors.DefaultMaxTrips,
	}
}

// BreakerConfig maps the settings onto a hosterrors.Config. Blank or invalid
// durations are left zero so the breaker's own defaults apply (Validate is
// what rejects an invalid value at load time).
func (c HostErrorsConfig) BreakerConfig() hosterrors.Config {
	parse := func(s string) time.Duration {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return 0
		}
		return d
	}
	return hosterrors.Config{
		Cooldown:    parse(c.Cooldown),
		MaxCooldown: parse(c.MaxCooldown),
		MaxTrips:    c.MaxTrips,
	}
}

// Validate rejects durations that do not parse or are not positive.
func (c HostErrorsConfig) Validate() error {
	for _, f := range []struct{ name, val string }{
		{"cooldown", c.Cooldown},
		{"max_cooldown", c.MaxCooldown},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil {
			return fmt.Errorf("http.host_errors.%s: %w", f.name, err)
		}
		if d <= 0 {
			return fmt.Errorf("http.host_errors.%s must be positive, got %q", f.name, f.val)
		}
	}
	return nil
}

// DefaultHTTPConfig returns the default HTTP config: the "preset" selector, so
// requests carry the honest, self-identifying Vigolium User-Agent unless the
// operator opts into "random" or a literal override.
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		UserAgent:  httpmsg.UserAgentPreset,
		HostErrors: DefaultHostErrorsConfig(),
	}
}
