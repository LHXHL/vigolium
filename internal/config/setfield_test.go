package config

import "testing"

// SetField must be able to set fields that the omitempty YAML round-trip drops
// when they hold their zero value. Before the schema-aware fallback these all
// failed with "unknown segment", so notifications could not be enabled at all.
func TestSetFieldCreatesOmitemptyFields(t *testing.T) {
	cases := []struct {
		key   string
		value string
		check func(s *Settings) bool
	}{
		{"notify.enabled", "true", func(s *Settings) bool { return s.Notify.Enabled }},
		{"notify.provider", "telegram", func(s *Settings) bool { return s.Notify.Provider == "telegram" }},
		{"notify.telegram.bot_token", "tok-123", func(s *Settings) bool { return s.Notify.Telegram.BotToken == "tok-123" }},
		{"notify.telegram.chat_id", "42", func(s *Settings) bool { return s.Notify.Telegram.ChatID == "42" }},
		{"notify.webhook.url", "https://hooks.acme.example/x", func(s *Settings) bool {
			return s.Notify.Webhook.URL == "https://hooks.acme.example/x"
		}},
		{"notify.severities", "high,critical", func(s *Settings) bool {
			return len(s.Notify.Severities) == 2 && s.Notify.Severities[0] == "high" && s.Notify.Severities[1] == "critical"
		}},
		{"server.enable_burp_bridge", "true", func(s *Settings) bool { return s.Server.EnableBurpBridge }},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			s := &Settings{}
			if err := SetField(s, tc.key, tc.value); err != nil {
				t.Fatalf("SetField(%q, %q) returned error: %v", tc.key, tc.value, err)
			}
			if !tc.check(s) {
				t.Fatalf("SetField(%q, %q) did not persist the value", tc.key, tc.value)
			}
		})
	}
}

// A typo'd key must still be rejected rather than silently creating a junk
// container that the settings unmarshal would drop.
func TestSetFieldRejectsUnknownKeys(t *testing.T) {
	for _, key := range []string{
		"notify.enabldd",      // wrong leaf
		"notfy.provider",      // wrong top-level section
		"notify.telegram.xyz", // wrong nested leaf
		"server.enable_burp_bridge.deeper",
	} {
		t.Run(key, func(t *testing.T) {
			s := &Settings{}
			if err := SetField(s, key, "true"); err == nil {
				t.Fatalf("SetField(%q) accepted an unknown key, want error", key)
			}
		})
	}
}

// Dynamic map fields accept arbitrary leaf keys (validated only up to the map).
func TestSetFieldDynamicMapKey(t *testing.T) {
	s := &Settings{}
	if err := SetField(s, "known_issue_scan.severity_overrides.CVE-2024-0001", "high"); err != nil {
		t.Fatalf("SetField into severity_overrides map returned error: %v", err)
	}
	if s.KnownIssueScan.SeverityOverrides["CVE-2024-0001"] != "high" {
		t.Fatalf("severity_overrides map entry not set: %+v", s.KnownIssueScan.SeverityOverrides)
	}
}
