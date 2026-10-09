package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func issueCodes(issues []Issue) map[string]string {
	out := map[string]string{}
	for _, is := range issues {
		out[is.Code] = is.Severity
	}
	return out
}

// The default config must validate clean, or `config validate` and doctor
// would flag every fresh install.
func TestValidateSettingsDefaultsClean(t *testing.T) {
	if issues := ValidateSettings(DefaultSettings()); len(issues) != 0 {
		t.Fatalf("default settings have issues: %+v", issues)
	}
}

func TestValidateScopeRules(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(s *ScopeConfig)
		code     string
		severity string
	}{
		{"empty pattern", func(s *ScopeConfig) { s.Path.Exclude = []string{""} }, IssueScopePatternInvalid, SeverityError},
		{"whitespace", func(s *ScopeConfig) { s.Host.Exclude = []string{" a.example"} }, IssueScopePatternInvalid, SeverityError},
		{"quote residue", func(s *ScopeConfig) { s.Host.Exclude = []string{`"a.example"`} }, IssueScopePatternInvalid, SeverityError},
		{"bracket residue", func(s *ScopeConfig) { s.Host.Exclude = []string{`["a.example`} }, IssueScopePatternInvalid, SeverityError},
		{"bad glob", func(s *ScopeConfig) { s.Path.Exclude = []string{`/a\`} }, IssueScopePatternInvalid, SeverityError},
		{"host scheme", func(s *ScopeConfig) { s.Host.Include = []string{"https://*.example.com"} }, IssueScopeHostHasSchemeOrPath, SeverityError},
		{"host path", func(s *ScopeConfig) { s.Host.Exclude = []string{"example.com/admin"} }, IssueScopeHostHasSchemeOrPath, SeverityError},
		{"host port", func(s *ScopeConfig) { s.Host.Include = []string{"*.example.com:8443"} }, IssueScopeHostHasPort, SeverityWarning},
		{"restrictive include", func(s *ScopeConfig) { s.Host.Include = []string{"app.example.com"} }, IssueScopeIncludeRestrictive, SeverityWarning},
		{"path no slash", func(s *ScopeConfig) { s.Path.Include = []string{"api/*"} }, IssueScopePathNoSlash, SeverityWarning},
		{"status invalid", func(s *ScopeConfig) { s.StatusCode.Exclude = []string{"4oo"} }, IssueScopeStatusInvalid, SeverityError},
		{"status bad range", func(s *ScopeConfig) { s.StatusCode.Exclude = []string{"500-400"} }, IssueScopeStatusInvalid, SeverityError},
		{"origin mode", func(s *ScopeConfig) { s.CLIOriginMode = "loose" }, IssueScopeOriginModeInvalid, SeverityError},
		{"body action", func(s *ScopeConfig) { s.BodySizeExceededAction = "explode" }, IssueScopeBodyActionInvalid, SeverityError},
		{"empty substring", func(s *ScopeConfig) { s.ResponseString.Exclude = []string{""} }, IssueScopePatternInvalid, SeverityError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *DefaultScopeConfig()
			tc.mutate(&s)
			codes := issueCodes(ValidateScope(s))
			if got, ok := codes[tc.code]; !ok || got != tc.severity {
				t.Fatalf("want %s/%s, got %v", tc.code, tc.severity, codes)
			}
		})
	}

	// Valid shapes raise nothing.
	s := *DefaultScopeConfig()
	s.Host.Include = []string{"*.example.com", "example.com"}
	s.Host.Exclude = []string{"admin.*", "[ab].example.com"}
	s.Path.Exclude = []string{"/logout", "*.php"}
	s.StatusCode.Exclude = []string{"404", "5xx", "30*", "400-499"}
	s.CLIOriginMode = "Strict"
	s.BodySizeExceededAction = "passive-only"
	if issues := ValidateScope(s); len(issues) != 0 {
		t.Fatalf("valid scope flagged: %+v", issues)
	}
}

// The shape a comma-split JSON list left in a real config: every pattern
// carries quote/bracket residue, so the scope matched nothing. The fix must be
// the cleaned list, ready to run.
func TestValidateScopeCommaSplitJSON(t *testing.T) {
	s := *DefaultScopeConfig()
	s.Host.Include = []string{`["app.example.com"`, `"api.example.com"]`}
	issues := ValidateScope(s)
	if !HasErrors(issues) {
		t.Fatalf("broken include not flagged: %+v", issues)
	}
	var fix string
	for _, is := range issues {
		if is.Code == IssueScopePatternInvalid {
			fix = is.Fix
		}
	}
	want := `vigolium config set scope.host.include '["app.example.com","api.example.com"]'`
	if fix != want {
		t.Fatalf("fix = %s\nwant  %s", fix, want)
	}
}

func TestValidateRecentTargets(t *testing.T) {
	s := *DefaultScopeConfig()
	s.Host.Include = []string{"old.example.org"}
	issues := ValidateRecentTargets(s, []string{"https://shop.example.com/", "api.example.com:8443"})
	if len(issues) != 1 || issues[0].Code != IssueScopeIncludeMatchesNoRecentTarget {
		t.Fatalf("got %+v", issues)
	}
	if issues := ValidateRecentTargets(s, []string{"https://old.example.org/x"}); len(issues) != 0 {
		t.Fatalf("matching target flagged: %+v", issues)
	}
	s.Host.Include = []string{"*.example.org"}
	if issues := ValidateRecentTargets(s, []string{"https://shop.example.com/"}); len(issues) != 0 {
		t.Fatalf("wildcard include flagged: %+v", issues)
	}
}

func TestValidateSettingsOASTAndSections(t *testing.T) {
	s := DefaultSettings()
	s.OAST.ServerURL = ""
	s.Spidering.MaxDepth = -1
	codes := issueCodes(ValidateSettings(s))
	if codes[IssueOASTServerMissing] != SeverityError {
		t.Fatalf("oast server missing not flagged: %v", codes)
	}
	if codes[IssueConfigValueInvalid] != SeverityError {
		t.Fatalf("section Validate() error not wrapped: %v", codes)
	}
	s = DefaultSettings()
	s.OAST.ServerURL = "ftp://oast.example"
	if issueCodes(ValidateSettings(s))[IssueOASTServerURLInvalid] != SeverityError {
		t.Fatal("bad oast server_url not flagged")
	}
	s = DefaultSettings()
	s.OAST.GracePeriod = -1
	if issueCodes(ValidateSettings(s))[IssueOASTIntervalInvalid] != SeverityError {
		t.Fatal("negative grace period not flagged")
	}
}

func TestValidateConfigFileUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("scope:\n  host:\n    includ: [a]\nnotify:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issues := ValidateConfigFile(path, &Settings{})
	if len(issues) != 1 || issues[0].Code != IssueConfigUnknownKey || issues[0].Key != "includ" || issues[0].Severity != SeverityWarning {
		t.Fatalf("got %+v", issues)
	}
	// A project overlay is checked against the profile shape: server is not an
	// overlay section, so it is inert there.
	if err := os.WriteFile(path, []byte("server:\n  port: 1\nscope:\n  cli_origin_mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issues = ValidateConfigFile(path, &ProfileSettings{})
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "server") {
		t.Fatalf("got %+v", issues)
	}
	if issues := ValidateConfigFile(filepath.Join(dir, "missing.yaml"), &Settings{}); issues != nil {
		t.Fatalf("missing file: %+v", issues)
	}
}

func TestSetProjectOverlayValue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	uuid := "11111111-2222-3333-4444-555555555555"
	path := ProjectConfigPath(uuid)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("spidering:\n  max_depth: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := DefaultSettings()
	if err := SetField(s, "scope.host.include", `["*.example.com"]`); err != nil {
		t.Fatal(err)
	}
	if _, err := SetProjectOverlayValue(uuid, "scope.host.include", s); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "max_depth: 3") || !strings.Contains(string(data), "'*.example.com'") ||
		strings.Contains(string(data), "exclude") {
		t.Fatalf("overlay = %s", data)
	}
	merged, err := LoadSettingsWithProject("", uuid)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Scope.Host.Include) != 1 || merged.Scope.Host.Include[0] != "*.example.com" {
		t.Fatalf("merged include = %q", merged.Scope.Host.Include)
	}

	// An unparseable overlay is refused, not replaced.
	if err := os.WriteFile(path, []byte("scope: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SetProjectOverlayValue(uuid, "scope.host.include", s); err == nil {
		t.Fatal("broken overlay was overwritten")
	}
	if data, _ := os.ReadFile(path); string(data) != "scope: [\n" {
		t.Fatalf("broken overlay changed: %q", data)
	}
}
