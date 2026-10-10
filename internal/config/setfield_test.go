package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

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

// List values: JSON and YAML flow lists are parsed against the declared type;
// the legacy comma form still works with every element checked. Before this,
// '["a","b"]' was comma-split into the patterns `["a"` and `"b"]`.
func TestSetFieldStructuredLists(t *testing.T) {
	ok := []struct {
		name, value string
		want        []string
	}{
		{"json list", `["a.example","b.example"]`, []string{"a.example", "b.example"}},
		{"yaml flow list", `[a.example, b.example]`, []string{"a.example", "b.example"}},
		{"comma form", `a.example,b.example`, []string{"a.example", "b.example"}},
		{"comma form trimmed", ` a.example , b.example `, []string{"a.example", "b.example"}},
		{"empty json list", `[]`, []string{}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			s := DefaultSettings()
			if err := SetField(s, "scope.host.include", tc.value); err != nil {
				t.Fatalf("SetField(%q) error: %v", tc.value, err)
			}
			got := s.Scope.Host.Include
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}

	bad := []struct{ name, value, want string }{
		{"unterminated json", `["a",`, "cannot parse"},
		{"numbers into strings", `[1,2]`, "expected a list of strings"},
		{"map into list", `{"a":1}`, "expected a list of strings"},
		{"empty value", ``, "empty value"},
		{"empty comma element", `a,,b`, "empty element"},
		{"empty json element", `["a",""]`, "empty string"},
		{"json residue in comma form", `"a","b"`, "fragment of a JSON list"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s := DefaultSettings()
			before := append([]string(nil), s.Scope.Host.Include...)
			err := SetField(s, "scope.host.include", tc.value)
			if err == nil {
				t.Fatalf("SetField(%q) accepted a bad value: %q", tc.value, s.Scope.Host.Include)
			}
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error %v does not wrap ErrInvalidValue", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if fmt.Sprint(s.Scope.Host.Include) != fmt.Sprint(before) {
				t.Fatalf("settings changed on a refused value: %q", s.Scope.Host.Include)
			}
		})
	}
}

func TestSetFieldListAdd(t *testing.T) {
	s := DefaultSettings()
	if err := SetField(s, "scope.host.exclude.add", "admin.example"); err != nil {
		t.Fatal(err)
	}
	if err := SetField(s, "scope.host.exclude.add", `["a.example","b.example"]`); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(s.Scope.Host.Exclude); got != "[admin.example a.example b.example]" {
		t.Fatalf("exclude = %s", got)
	}
	for _, v := range []string{`"x"`, ``, `[1]`, `["ok",`} {
		if err := SetField(s, "scope.host.exclude.add", v); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf(".add %q: err = %v, want ErrInvalidValue", v, err)
		}
	}
	if err := SetField(s, "scope.host.exclude.clear", ""); err != nil {
		t.Fatal(err)
	}
	if len(s.Scope.Host.Exclude) != 0 {
		t.Fatalf("clear left %q", s.Scope.Host.Exclude)
	}
}

// A map field takes a JSON/YAML object, and the object replaces the map rather
// than merging into it (yaml.v3 merges into an existing map on decode).
func TestSetFieldMapValue(t *testing.T) {
	s := DefaultSettings()
	if err := SetField(s, "known_issue_scan.severity_overrides.old-template", "low"); err != nil {
		t.Fatal(err)
	}
	if err := SetField(s, "known_issue_scan.severity_overrides", `{"x":"high"}`); err != nil {
		t.Fatal(err)
	}
	if got := s.KnownIssueScan.SeverityOverrides; len(got) != 1 || got["x"] != "high" {
		t.Fatalf("severity_overrides = %v", got)
	}
	if err := SetField(s, "known_issue_scan.severity_overrides", `x=high`); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-object map value: err = %v", err)
	}
	if err := SetField(s, "known_issue_scan.severity_overrides", `{"x":[1]}`); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("wrong element type: err = %v", err)
	}
}

// A value that introduces an error-level validation issue at the key is
// refused; an unrelated pre-existing issue does not block other edits.
func TestSetFieldRefusesInvalidScope(t *testing.T) {
	s := DefaultSettings()
	err := SetField(s, "scope.host.include", `["https://a.example/app"]`)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "scope.host.include") {
		t.Fatalf("scheme in host pattern: err = %v", err)
	}
	if fmt.Sprint(s.Scope.Host.Include) != "[*]" {
		t.Fatalf("refused value was applied: %q", s.Scope.Host.Include)
	}
	if err := SetField(s, "scope.cli_origin_mode", "loose"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad origin mode: err = %v", err)
	}

	// Pre-existing broken value elsewhere: editing another key still works.
	s.Scope.Path.Include = []string{`["/api"`}
	if err := SetField(s, "scope.host.include", `["*.example.com"]`); err != nil {
		t.Fatalf("unrelated pre-existing issue blocked the edit: %v", err)
	}
	// Multi-step edits of section-level rules are not blocked.
	if err := SetField(s, "storage.enabled", "true"); err != nil {
		t.Fatalf("storage.enabled before bucket was refused: %v", err)
	}
}

// The runtime-only yaml:"-" fields survive the round-trip.
func TestSetFieldKeepsUnserializedFields(t *testing.T) {
	s := DefaultSettings()
	s.Database.ReadIntent = true
	if err := SetField(s, "notify.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if !s.Database.ReadIntent {
		t.Fatal("ReadIntent was reset by SetField")
	}
}

// A section (struct) key given a scalar is refused, not a panic.
func TestSetFieldSectionKeyScalar(t *testing.T) {
	s := DefaultSettings()
	if err := SetField(s, "scope.host", "a.example"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err = %v, want ErrInvalidValue", err)
	}
	if err := SetField(s, "scope.host", `{"include":["*.example.com"],"exclude":[]}`); err != nil {
		t.Fatalf("object into section: %v", err)
	}
	if fmt.Sprint(s.Scope.Host.Include) != "[*.example.com]" {
		t.Fatalf("include = %q", s.Scope.Host.Include)
	}
}
