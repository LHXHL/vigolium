package config

import "testing"

func TestDiscoveryConfig_ValidateJSTemplatePersistence(t *testing.T) {
	if got := DefaultDiscoveryConfig().JSTangle.MaxPersistedJSTemplates; got != 2000 {
		t.Fatalf("default max_persisted_js_templates = %d, want 2000", got)
	}
	cases := []struct {
		name    string
		mutate  func(*DiscoveryConfig)
		wantErr bool
	}{
		{"negative cap", func(c *DiscoveryConfig) { c.JSTangle.MaxPersistedJSTemplates = -1 }, true},
		{"zero cap means default", func(c *DiscoveryConfig) { c.JSTangle.MaxPersistedJSTemplates = 0 }, false},
		{"emit statuses", func(c *DiscoveryConfig) { c.JSTangle.PersistNotFoundEmitStatuses = []int{400, 422} }, false},
		{"empty emit statuses", func(c *DiscoveryConfig) { c.JSTangle.PersistNotFoundEmitStatuses = []int{} }, false},
		{"bogus emit status", func(c *DiscoveryConfig) { c.JSTangle.PersistNotFoundEmitStatuses = []int{4000} }, true},
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
