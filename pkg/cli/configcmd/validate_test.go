package configcmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

type capturedEnvelope struct {
	cmd   *cobra.Command
	items []config.Issue
	extra map[string]any
}

func validateDeps(t *testing.T, cfg string, targets []string) (Deps, *capturedEnvelope) {
	t.Helper()
	got := &capturedEnvelope{}
	return Deps{
		ConfigFlag: func() string { return cfg },
		JSON:       func() bool { return true },
		WriteJSON: func(cmd *cobra.Command, legacyKey string, items any, total int, extra map[string]any) error {
			got.cmd = cmd
			got.items = items.([]config.Issue)
			got.extra = extra
			if total != len(got.items) {
				t.Errorf("total %d != len(items) %d", total, len(got.items))
			}
			// The items must serialize as an array (never null) of issue objects.
			b, err := json.Marshal(items)
			if err != nil || b[0] != '[' {
				t.Errorf("items marshal to %s (%v)", b, err)
			}
			return nil
		},
		RecentScanTargets: func(project string, n int) ([]string, error) {
			if targets == nil {
				return nil, errors.New("no database")
			}
			return targets, nil
		},
	}, got
}

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func codeOf(err error) apicontract.ErrorCode {
	var coded clicommon.CodedError
	if errors.As(err, &coded) {
		return coded.Code()
	}
	return ""
}

func TestConfigValidateClean(t *testing.T) {
	deps, got := validateDeps(t, writeCfg(t, "{}\n"), nil)
	cmd := &cobra.Command{Use: "validate"}
	if err := runConfigValidate(cmd, deps, validateOptions{Recent: 5}); err != nil {
		t.Fatalf("clean config: %v", err)
	}
	if got.cmd != cmd || len(got.items) != 0 || got.extra["valid"] != true {
		t.Fatalf("envelope: %+v", got)
	}
}

// The user's real broken shape: a JSON list that `config set` comma-split.
func TestConfigValidateErrorsExit1(t *testing.T) {
	cfg := writeCfg(t, "scope:\n  host:\n    include: ['[\"app.example.com\"', '\"api.example.com\"]']\n")
	deps, got := validateDeps(t, cfg, nil)
	err := runConfigValidate(nil, deps, validateOptions{Recent: 5})
	if codeOf(err) != apicontract.CodeConfigInvalid {
		t.Fatalf("err = %v, want config_invalid", err)
	}
	var usage clicommon.UsageError
	if errors.As(err, &usage) {
		t.Fatal("validation failure must not be a usage error (exit 2)")
	}
	if got.extra["valid"] != false || got.extra["errors"].(int) == 0 {
		t.Fatalf("envelope extra: %+v", got.extra)
	}
}

func TestConfigValidateWarningsAndStrict(t *testing.T) {
	cfg := writeCfg(t, "scope:\n  host:\n    include: [old.example.org]\n  bogus_key: 1\n")
	deps, got := validateDeps(t, cfg, []string{"https://shop.example.com/"})
	if err := runConfigValidate(nil, deps, validateOptions{Recent: 5}); err != nil {
		t.Fatalf("warnings only, not strict: %v", err)
	}
	codes := map[string]bool{}
	for _, is := range got.items {
		codes[is.Code] = true
	}
	for _, want := range []string{config.IssueScopeIncludeRestrictive, config.IssueScopeIncludeMatchesNoRecentTarget, config.IssueConfigUnknownKey} {
		if !codes[want] {
			t.Errorf("missing %s in %+v", want, got.items)
		}
	}
	if err := runConfigValidate(nil, deps, validateOptions{Recent: 5, Strict: true}); codeOf(err) != apicontract.CodeConfigInvalid {
		t.Fatalf("--strict with warnings: err = %v", err)
	}
	if got.extra["valid"] != false {
		t.Fatalf("--strict ok = %v", got.extra["valid"])
	}
	// --recent 0 skips the DB rule.
	if err := runConfigValidate(nil, deps, validateOptions{Recent: 0}); err != nil {
		t.Fatal(err)
	}
	for _, is := range got.items {
		if is.Code == config.IssueScopeIncludeMatchesNoRecentTarget {
			t.Fatal("--recent 0 still ran the recent-target rule")
		}
	}
}

func TestConfigValidateProjectOverride(t *testing.T) {
	cfg := writeCfg(t, "{}\n")
	uuid := "11111111-2222-3333-4444-555555555555"
	path := config.ProjectConfigPath(uuid)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("scope:\n  cli_origin_mode: loose\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps, got := validateDeps(t, cfg, nil)
	if err := runConfigValidate(nil, deps, validateOptions{Recent: 5}); err != nil {
		t.Fatalf("global only: %v", err)
	}
	err := runConfigValidate(nil, deps, validateOptions{Project: uuid, Recent: 5})
	if codeOf(err) != apicontract.CodeConfigInvalid {
		t.Fatalf("project override not validated: %v", err)
	}
	if len(got.items) != 1 || got.items[0].Code != config.IssueScopeOriginModeInvalid {
		t.Fatalf("items: %+v", got.items)
	}
}

func TestConfigValidateUnparseableConfig(t *testing.T) {
	deps, got := validateDeps(t, writeCfg(t, "scope: [\n"), nil)
	err := runConfigValidate(nil, deps, validateOptions{Recent: 5})
	if codeOf(err) != apicontract.CodeConfigInvalid {
		t.Fatalf("err = %v", err)
	}
	if len(got.items) != 1 || got.items[0].Code != config.IssueConfigLoadFailed {
		t.Fatalf("items: %+v", got.items)
	}
}

func TestConfigValidateRecentUsage(t *testing.T) {
	deps, _ := validateDeps(t, writeCfg(t, "{}\n"), nil)
	var usage clicommon.UsageError
	if err := runConfigValidate(nil, deps, validateOptions{Recent: -1}); !errors.As(err, &usage) {
		t.Fatalf("--recent -1: %v", err)
	}
}
