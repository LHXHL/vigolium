package configcmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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
		"empty key=value":   {"=value"},
		"three args no '='": {"a", "b", "c"},
		"single bare key":   {"notify.enabled"},
		"unknown key":       {"no_such_section.no_such_key", "1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runConfigSet(deps, args)
			var usage clicommon.UsageError
			if !errors.As(err, &usage) {
				t.Fatalf("runConfigSet(%q) = %v, want a UsageError", args, err)
			}
		})
	}
}
