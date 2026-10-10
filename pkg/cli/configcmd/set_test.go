package configcmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// A malformed `config set` command line and a key that names no setting are
// both mistakes on the command line (exit 2), not failures to write the config.
func TestConfigSetUsageErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}

	for name, args := range map[string][]string{
		"empty key=value":    {"=value"},
		"three args no '='":  {"a", "b", "c"},
		"single bare key":    {"notify.enabled"},
		"unknown key":        {"no_such_section.no_such_key", "1"},
		"unparseable list":   {"scope.host.include", `["a",`},
		"wrong element type": {"scope.host.include", `[1,2]`},
		"empty element":      {"scope.host.include", `a,,b`},
		"scheme in host":     {"scope.host.include", `["https://a.example"]`},
		"add residue":        {"scope.host.exclude.add", `"x"`},
	} {
		t.Run(name, func(t *testing.T) {
			err := runConfigSet(nil, deps, args)
			var usage clicommon.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("runConfigSet(%q) = %v, want a UsageError", args, err)
			}
		})
	}
}

// A refused value leaves the file byte-for-byte unchanged; an accepted JSON
// list lands as a real list.
func TestConfigSetStructuredValueFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{ConfigFlag: func() string { return cfg }}

	if err := runConfigSet(nil, deps, []string{"scope.host.include", `["a.example","*.b.example"]`}); err != nil {
		t.Fatal(err)
	}
	settings, err := config.LoadSettings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.Scope.Host.Include; len(got) != 2 || got[0] != "a.example" || got[1] != "*.b.example" {
		t.Fatalf("include = %q", got)
	}

	before, _ := os.ReadFile(cfg)
	if err := runConfigSet(nil, deps, []string{"scope.host.include", `["a.example",`}); err == nil {
		t.Fatal("broken list accepted")
	}
	after, _ := os.ReadFile(cfg)
	if string(before) != string(after) {
		t.Fatalf("refused value changed the file:\n%s\n---\n%s", before, after)
	}
}
