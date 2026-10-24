package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

func paceSettings(mutate func(*config.ScanningPaceConfig)) *config.Settings {
	s := &config.Settings{
		ScanningPace: *config.DefaultScanningPaceConfig(),
		Discovery:    *config.DefaultDiscoveryConfig(),
	}
	if mutate != nil {
		mutate(&s.ScanningPace)
	}
	return s
}

// TestDiscoveryRateLimitPrecedence pins what reaches the engine. The headline is
// the LAST case: a config file alone must not start pacing discovery, because the
// global rate carries a 100 rps default and every existing scan would slow down.
func TestDiscoveryRateLimitPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		opts     *types.Options
		settings *config.Settings
		want     int
	}{
		{
			name:     "nothing configured is unpaced",
			opts:     &types.Options{},
			settings: paceSettings(nil),
			want:     0,
		},
		{
			name:     "no settings at all is unpaced",
			opts:     &types.Options{},
			settings: nil,
			want:     0,
		},
		{
			name:     "explicit section rate is enforced",
			opts:     &types.Options{},
			settings: paceSettings(func(p *config.ScanningPaceConfig) { p.Discovery.RateLimit = 7 }),
			want:     7,
		},
		{
			name:     "section rate outranks a typed global",
			opts:     &types.Options{RateLimit: 50, RateLimitExplicitlySet: true},
			settings: paceSettings(func(p *config.ScanningPaceConfig) { p.Discovery.RateLimit = 7 }),
			want:     7,
		},
		{
			name:     "typed global rate is enforced",
			opts:     &types.Options{RateLimit: 5, RateLimitExplicitlySet: true},
			settings: paceSettings(nil),
			want:     5,
		},
		{
			name:     "the global default is NOT enforced",
			opts:     &types.Options{RateLimit: 100},
			settings: paceSettings(nil),
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Runner{options: tt.opts, settings: tt.settings}
			if got := r.discoveryRateLimit(); got != tt.want {
				t.Fatalf("discoveryRateLimit() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildDeparosConfigCarriesRate proves the resolved rate actually lands on
// the source config, which is where the engine reads it from.
func TestBuildDeparosConfigCarriesRate(t *testing.T) {
	r := &Runner{
		options:  &types.Options{Targets: []string{"https://example.com"}, Concurrency: 25},
		settings: paceSettings(func(p *config.ScanningPaceConfig) { p.Discovery.RateLimit = 11 }),
	}
	if got := r.buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).RateLimit; got != 11 {
		t.Fatalf("DeparosDiscoveryConfig.RateLimit = %d, want 11", got)
	}

	unpaced := &Runner{
		options:  &types.Options{Targets: []string{"https://example.com"}, Concurrency: 25, RateLimit: 100},
		settings: paceSettings(nil),
	}
	if got := unpaced.buildDeparosConfig(nil, resolvedDiscoveryWordlists{}).RateLimit; got != 0 {
		t.Fatalf("unconfigured DeparosDiscoveryConfig.RateLimit = %d, want 0", got)
	}
}

// TestDiscoveryConcurrency pins the thread count the phase header prints, which
// used to be the global value while the engine ran on the section's.
func TestDiscoveryConcurrency(t *testing.T) {
	section := paceSettings(func(p *config.ScanningPaceConfig) { p.Discovery.Concurrency = 4 })

	r := &Runner{options: &types.Options{Concurrency: 25}, settings: section}
	if got := r.discoveryConcurrency(); got != 4 {
		t.Errorf("section override: got %d, want 4", got)
	}

	typed := &Runner{
		options:  &types.Options{Concurrency: 25, ConcurrencyExplicitlySet: true},
		settings: section,
	}
	if got := typed.discoveryConcurrency(); got != 25 {
		t.Errorf("a typed --concurrency must win: got %d, want 25", got)
	}

	bare := &Runner{options: &types.Options{Concurrency: 25}}
	if got := bare.discoveryConcurrency(); got != 25 {
		t.Errorf("no settings: got %d, want 25", got)
	}
}

// TestDiscoveryWirePace pins discovery's brute-force width and protocol: by
// default wordlist fuzzing runs as wide as the per-host slot cap over the best
// protocol, an explicit -c sets the pace for it too, and the discovery.engine
// keys override both.
func TestDiscoveryWirePace(t *testing.T) {
	withEngine := func(protocol string, brute int) *config.Settings {
		s := paceSettings(nil)
		s.Discovery.Engine.Protocol = protocol
		s.Discovery.Engine.BruteForceConcurrency = brute
		return s
	}
	tests := []struct {
		name        string
		opts        *types.Options
		settings    *config.Settings
		concurrency int
		wantBrute   int
		wantProto   string
	}{
		{"defaults: per-host cap, auto", &types.Options{}, paceSettings(nil), 25, types.DefaultMaxPerHost, "auto"},
		{"no settings", &types.Options{}, nil, 25, types.DefaultMaxPerHost, "auto"},
		{"never below the phase concurrency", &types.Options{}, paceSettings(nil), 60, 60, "auto"},
		{"scanning_pace.max_per_host", &types.Options{}, paceSettings(func(p *config.ScanningPaceConfig) { p.MaxPerHost = 10 }), 25, 25, "auto"},
		{"typed --max-per-host", &types.Options{MaxPerHost: 100, MaxPerHostExplicitlySet: true}, paceSettings(nil), 25, 100, "auto"},
		{"explicit -c is the pace", &types.Options{Concurrency: 5, ConcurrencyExplicitlySet: true}, paceSettings(nil), 5, 5, "auto"},
		{"engine keys override", &types.Options{}, withEngine("HTTP1", 200), 25, 200, "http1"},
		{"protocol alias is canonicalized", &types.Options{}, withEngine("h2", 0), 25, types.DefaultMaxPerHost, "http2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runner{options: tc.opts, settings: tc.settings}
			brute, proto := r.discoveryWirePace(tc.concurrency)
			if brute != tc.wantBrute || proto != tc.wantProto {
				t.Errorf("discoveryWirePace = %d, %q; want %d, %q", brute, proto, tc.wantBrute, tc.wantProto)
			}
		})
	}
}
