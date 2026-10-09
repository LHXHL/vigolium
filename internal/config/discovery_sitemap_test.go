package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDiscoveryConfig_Sitemap(t *testing.T) {
	def := DefaultDiscoveryConfig().Sitemap
	if !def.IsEnabled() || !def.FollowsIndex() || def.MaxURLs != 2000 || def.PerShape != 3 {
		t.Fatalf("default sitemap config = %+v, want enabled, follow_index, 2000, 3", def)
	}

	var parsed DiscoveryConfig
	if err := yaml.Unmarshal([]byte("sitemap:\n  enabled: false\n  follow_index: false\n  max_urls: 50\n"), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Sitemap.IsEnabled() || parsed.Sitemap.FollowsIndex() || parsed.Sitemap.MaxURLs != 50 {
		t.Fatalf("parsed sitemap config = %+v", parsed.Sitemap)
	}

	cases := []struct {
		name    string
		mutate  func(*DiscoveryConfig)
		wantErr bool
	}{
		{"negative max_urls", func(c *DiscoveryConfig) { c.Sitemap.MaxURLs = -1 }, true},
		{"negative per_shape", func(c *DiscoveryConfig) { c.Sitemap.PerShape = -1 }, true},
		{"zero means default", func(c *DiscoveryConfig) { c.Sitemap.MaxURLs, c.Sitemap.PerShape = 0, 0 }, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultDiscoveryConfig()
			tt.mutate(c)
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
