package cli

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/types"
)

// flagCmd returns a command whose flag set has the named flags marked as typed.
func flagCmd(t *testing.T, typed map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "x"}
	f := cmd.Flags()
	f.StringSlice("discovery-extensions", nil, "")
	f.Int("discovery-max-depth", 0, "")
	f.StringArray("known-issue-scan-templates-dir", nil, "")
	f.StringArray("known-issue-scan-templates", nil, "")
	for name, v := range typed {
		if err := f.Set(name, v); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

func TestNormalizeDiscoveryExtensions(t *testing.T) {
	got := normalizeDiscoveryExtensions([]string{".php", " bak ", "php", ".tar.gz,,.old"})
	want := []string{"php", "bak", "tar.gz", "old"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplyDiscoveryFlagOverrides(t *testing.T) {
	dc := config.DefaultDiscoveryConfig()
	opts := &types.Options{DiscoveryExtensions: []string{".php", ".bak"}, DiscoveryMaxDepth: 2}
	cmd := flagCmd(t, map[string]string{"discovery-extensions": ".php,.bak", "discovery-max-depth": "2"})
	if err := applyDiscoveryFlagOverrides(cmd, dc, opts); err != nil {
		t.Fatal(err)
	}
	if !dc.Extensions.TestCustom || !reflect.DeepEqual(dc.Extensions.CustomList, []string{"php", "bak"}) {
		t.Errorf("extensions = %+v", dc.Extensions)
	}
	// An explicit list is swept, not held behind the confirmation gate.
	if dc.Extensions.ConfirmRequired == nil || *dc.Extensions.ConfirmRequired {
		t.Error("explicit extensions left behind the confirm gate")
	}
	if !dc.Recursion.Enabled || dc.Recursion.MaxDepth != 2 {
		t.Errorf("recursion = %+v", dc.Recursion)
	}

	// Depth 0 turns recursion off; untyped flags leave the config alone.
	dc = config.DefaultDiscoveryConfig()
	if err := applyDiscoveryFlagOverrides(flagCmd(t, map[string]string{"discovery-max-depth": "0"}), dc, &types.Options{}); err != nil {
		t.Fatal(err)
	}
	if dc.Recursion.Enabled || dc.Extensions.ConfirmRequired != nil {
		t.Errorf("depth 0 / untyped extensions: %+v %+v", dc.Recursion, dc.Extensions)
	}

	if err := applyDiscoveryFlagOverrides(flagCmd(t, map[string]string{"discovery-max-depth": "-1"}), config.DefaultDiscoveryConfig(), &types.Options{DiscoveryMaxDepth: -1}); err == nil {
		t.Error("negative depth accepted")
	}
	if err := applyDiscoveryFlagOverrides(flagCmd(t, map[string]string{"discovery-extensions": ","}), config.DefaultDiscoveryConfig(), &types.Options{DiscoveryExtensions: []string{"", ""}}); err == nil {
		t.Error("empty extension list accepted")
	}
}

func TestApplyKnownIssueScanTemplateFlags(t *testing.T) {
	// One directory: it is the templates dir, nothing narrows the run.
	kc := &config.KnownIssueScanConfig{}
	applyKnownIssueScanTemplateFlags(flagCmd(t, map[string]string{"known-issue-scan-templates-dir": "/a"}), kc,
		&types.Options{KnownIssueScanTemplatesDirs: []string{"/a"}})
	if kc.TemplatesDir != "/a" || kc.Templates != nil {
		t.Errorf("one dir: %+v", kc)
	}

	// Several directories, or any single template: exactly the named set runs.
	kc = &config.KnownIssueScanConfig{TemplatesDir: "/cfg"}
	applyKnownIssueScanTemplateFlags(flagCmd(t, map[string]string{"known-issue-scan-templates": "x.yaml"}), kc,
		&types.Options{KnownIssueScanTemplates: []string{"x.yaml"}})
	if kc.TemplatesDir != "/cfg" || !reflect.DeepEqual(kc.Templates, []string{"x.yaml"}) {
		t.Errorf("template only: %+v", kc)
	}
	kc = &config.KnownIssueScanConfig{}
	applyKnownIssueScanTemplateFlags(flagCmd(t, map[string]string{"known-issue-scan-templates-dir": "/a"}), kc,
		&types.Options{KnownIssueScanTemplatesDirs: []string{"/a", "/b"}, KnownIssueScanTemplates: []string{"y.yaml"}})
	if kc.TemplatesDir != "/a" || !reflect.DeepEqual(kc.Templates, []string{"/a", "/b", "y.yaml"}) {
		t.Errorf("dirs + template: %+v", kc)
	}
}
