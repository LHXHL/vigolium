package config

import "testing"

func TestDiscoveryValidate_WordlistTier(t *testing.T) {
	for _, tier := range []string{"", "auto", "short", "long", "large", "Large"} {
		c := DefaultDiscoveryConfig()
		c.Wordlists.Tier = tier
		if err := c.Validate(); err != nil {
			t.Errorf("tier %q rejected: %v", tier, err)
		}
	}
	c := DefaultDiscoveryConfig()
	c.Wordlists.Tier = "medium"
	if err := c.Validate(); err == nil {
		t.Error("tier \"medium\" accepted, want a validation error")
	}
}
