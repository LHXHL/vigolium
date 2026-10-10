package runner

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/types"
)

// Extension fixtures: one active JS, one passive JS (tagged "headers"), one
// passive YAML. IDs become ext-a, ext-csp-check, ext-yaml-p.
var extFixtures = map[string]string{
	"a.js": `module.exports = {
  id: "a", name: "Alpha probe", type: "active", severity: "low",
  scanPerRequest: function(ctx) { return null; }
};`,
	"csp_check.js": `module.exports = {
  id: "csp-check", name: "CSP check", type: "passive", severity: "info", tags: ["headers"],
  scanPerRequest: function(ctx) { return null; }
};`,
	"yaml_p.vgm.yaml": `id: yaml-p
name: YAML passive
type: passive
severity: info
scope: response
rules:
  - match:
      response_header: X-Powered-By
    finding:
      name: "X-Powered-By exposed"
      severity: info
`,
}

// extRunner builds a Runner whose extension engine loaded the fixtures either
// through the extension directory (dir) or as explicit --ext paths.
func extRunner(t *testing.T, explicit bool, opts *types.Options) (*Runner, *jsext.Engine) {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range extFixtures {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	cfg := config.ExtensionsConfig{Enabled: true}
	if explicit {
		cfg.CustomDir = paths
	} else {
		cfg.ExtensionDir = dir
	}
	engine, err := jsext.NewEngine(&cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if n := len(engine.ActiveModules()) + len(engine.PassiveModules()); n != 3 {
		t.Fatalf("engine loaded %d extension modules, want 3", n)
	}
	settings := &config.Settings{}
	settings.DynamicAssessment.Extensions = cfg
	return &Runner{options: opts, settings: settings}, engine
}

func selectedIDs(sel extensionSelection) (active, passive []string) {
	for _, m := range sel.Active {
		active = append(active, m.ID())
	}
	for _, m := range sel.Passive {
		passive = append(passive, m.ID())
	}
	sort.Strings(active)
	sort.Strings(passive)
	return active, passive
}

func TestFilterExtensionModulesMatrix(t *testing.T) {
	all := []string{"all"}
	allExtPassive := []string{"ext-csp-check", "ext-yaml-p"}
	// The options each flag produces after the CLI's resolveModuleSelection.
	selections := []struct {
		name string
		opts types.Options
		// want per load mode: [0] explicit --ext, [1] extension directory
		wantActive  [2][]string
		wantPassive [2][]string
	}{
		{
			name:        "--passive-only",
			opts:        types.Options{Modules: nil, PassiveModules: all},
			wantPassive: [2][]string{allExtPassive, allExtPassive},
		},
		{
			name:       "--no-passive",
			opts:       types.Options{Modules: all, PassiveModules: nil},
			wantActive: [2][]string{{"ext-a"}, {"ext-a"}},
		},
		{
			name:       "--module-id ext-a",
			opts:       types.Options{Modules: []string{"ext-a"}, PassiveModules: []string{"ext-a"}},
			wantActive: [2][]string{{"ext-a"}, {"ext-a"}},
		},
		{
			// Only built-ins named: explicit --ext extensions still run, directory
			// auto-loads do not.
			name:        "--module-id sqli_error_based",
			opts:        types.Options{Modules: []string{"sqli_error_based"}, PassiveModules: []string{"sqli_error_based"}},
			wantActive:  [2][]string{{"ext-a"}, nil},
			wantPassive: [2][]string{allExtPassive, nil},
		},
		{
			// -m narrows the active side only (passive stays "all"); the pattern
			// names ext-csp-check, so the unnamed active extension is dropped in
			// both modes.
			name:        "-m csp",
			opts:        types.Options{Modules: []string{"csp_misconfig"}, PassiveModules: all, ModulePatterns: []string{"csp"}},
			wantPassive: [2][]string{allExtPassive, allExtPassive},
		},
		{
			// Direct-path shape: -m narrows both categories.
			name:        "-m csp (both narrowed)",
			opts:        types.Options{Modules: []string{"csp_misconfig"}, PassiveModules: []string{"csp_misconfig"}, ModulePatterns: []string{"csp"}},
			wantPassive: [2][]string{{"ext-csp-check"}, {"ext-csp-check"}},
		},
		{
			name:        "--module-tag headers",
			opts:        types.Options{Modules: []string{"x"}, PassiveModules: []string{"x"}, ModuleTags: []string{"headers"}},
			wantPassive: [2][]string{{"ext-csp-check"}, {"ext-csp-check"}},
		},
		{
			// -m with no built-in match: the CLI passes the raw pattern through.
			name:        "-m ext-a (pattern passthrough)",
			opts:        types.Options{Modules: []string{"ext-a"}, PassiveModules: all, ModulePatterns: []string{"ext-a"}},
			wantActive:  [2][]string{{"ext-a"}, {"ext-a"}},
			wantPassive: [2][]string{allExtPassive, allExtPassive},
		},
		{
			name:        "none",
			opts:        types.Options{Modules: all, PassiveModules: all},
			wantActive:  [2][]string{{"ext-a"}, {"ext-a"}},
			wantPassive: [2][]string{allExtPassive, allExtPassive},
		},
	}

	for _, sc := range selections {
		for mode, explicit := range []bool{true, false} {
			label := "dir"
			if explicit {
				label = "--ext"
			}
			t.Run(sc.name+"/"+label, func(t *testing.T) {
				opts := sc.opts
				r, engine := extRunner(t, explicit, &opts)
				sel := r.selectExtensionModules(engine)
				gotA, gotP := selectedIDs(sel)
				if !equalIDs(gotA, sc.wantActive[mode]) || !equalIDs(gotP, sc.wantPassive[mode]) {
					t.Fatalf("active=%v passive=%v, want active=%v passive=%v (%s)",
						gotA, gotP, sc.wantActive[mode], sc.wantPassive[mode], sel.summary())
				}
				if len(sel.Unknown) != 0 {
					t.Errorf("Unknown = %v, want none", sel.Unknown)
				}
				if got := sel.loaded(); got != 3 {
					t.Errorf("selected+skipped = %d, want 3", got)
				}
			})
		}
	}
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFilterExtensionModulesSummary(t *testing.T) {
	r, engine := extRunner(t, false, &types.Options{Modules: nil, PassiveModules: []string{"all"}})
	got := r.selectExtensionModules(engine).summary()
	want := "extensions: 0 active, 2 passive selected; 1 skipped (1 --passive-only)"
	if got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func dastPlan() NativeScanPlan {
	return NativeScanPlan{Steps: []NativePhaseStep{{Phase: PhaseDynamicAssessment, Enabled: true}}}
}

func TestValidateExtensionSelectionUnknownID(t *testing.T) {
	opts := &types.Options{Modules: []string{"ext-nope"}, PassiveModules: []string{"ext-nope"}}
	r, engine := extRunner(t, true, opts)
	err := r.validateExtensionSelection(dastPlan(), engine)
	if !errors.Is(err, ErrUnknownExtensionModule) {
		t.Fatalf("err = %v, want ErrUnknownExtensionModule", err)
	}

	// No dynamic-assessment phase: extension modules never run, nothing to check.
	if err := r.validateExtensionSelection(NativeScanPlan{}, engine); err != nil {
		t.Errorf("no DA phase: err = %v, want nil", err)
	}

	// No engine at all (extensions disabled): still a usage error.
	if err := r.validateExtensionSelection(dastPlan(), nil); !errors.Is(err, ErrUnknownExtensionModule) {
		t.Errorf("nil engine: err = %v, want ErrUnknownExtensionModule", err)
	}

	// A known ID passes.
	r.options = &types.Options{Modules: []string{"ext-a"}, PassiveModules: []string{"ext-a"}}
	if err := r.validateExtensionSelection(dastPlan(), engine); err != nil {
		t.Errorf("ext-a: err = %v, want nil", err)
	}

	// An unmatched -m pattern is fuzzy, so it warns elsewhere rather than failing.
	r.options = &types.Options{Modules: []string{"ext-nope"}, PassiveModules: []string{"all"}, ModulePatterns: []string{"ext-nope"}}
	if err := r.validateExtensionSelection(dastPlan(), engine); err != nil {
		t.Errorf("-m ext-nope: err = %v, want nil", err)
	}
}
