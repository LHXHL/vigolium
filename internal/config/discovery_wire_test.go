package config

import (
	"testing"

	deparosconfig "github.com/vigolium/vigolium/pkg/deparos/config"
)

func TestDiscoveryEngineWireSettingsValidate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		brute    int
		wantErr  bool
	}{
		{"defaults", "", 0, false},
		{"auto", "auto", 64, false},
		{"http3", "HTTP3", 0, false},
		{"alias", "h2", 0, false},
		{"unknown protocol", "spdy", 0, true},
		{"negative brute force", "auto", -1, true},
		{"brute force over cap", "auto", deparosconfig.MaxBruteForceThreads + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultDiscoveryConfig()
			c.Engine.Protocol = tc.protocol
			c.Engine.BruteForceConcurrency = tc.brute
			if err := c.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
