package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/types"
)

const overlayTestProject = "0a0a0a0a-1111-2222-3333-444444444444"

// writeProjectOverlay writes body as projectUUID's overlay under the current HOME.
func writeProjectOverlay(t *testing.T, projectUUID, body string) {
	t.Helper()
	path := config.ProjectConfigPath(projectUUID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	config.InvalidateProjectOverlay(projectUUID)
}

// TestProjectOverlayHonouredByScanResolver: the settings `vigolium scan` loads
// carry the resolved project's overlay (global → project), and the scanning
// profile and CLI flags still outrank it in resolveNativeScanOptions.
func TestProjectOverlayHonouredByScanResolver(t *testing.T) {
	resetProjectScopeGlobals(t)
	swapGlobal(t, &dbPathEnvPinned, false)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir()) // no ./vigolium-configs.yaml: global settings are the defaults
	clicommon.ResetConfigWarningsForTest()

	profiles := writeIntensityProfiles(t)
	if err := os.WriteFile(filepath.Join(profiles, "narrow.yaml"),
		[]byte("scope:\n  host:\n    include: [\"profile.example.com\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeProjectOverlay(t, overlayTestProject,
		"scope:\n  host:\n    include: [\"app.example.com\"]\nscanning_pace:\n  concurrency: 7\n")
	globalInclude := config.DefaultSettings().Scope.Host.Include

	resolve := func(t *testing.T, args ...string) (*types.Options, *config.Settings) {
		t.Helper()
		clicommon.ResetProjectResolutionForTest()
		settings, err := loadProjectSettings("")
		if err != nil {
			t.Fatalf("loadProjectSettings: %v", err)
		}
		settings.ScanningStrategy.ProfilesDir = profiles
		cmd := newResolveTestCmd(t, args...)
		opts := types.DefaultOptions()
		opts.Silent = true
		opts.Concurrency = globalConcurrency
		opts.MaxPerHost = globalMaxPerHost
		opts.RateLimit = globalRateLimit
		if _, err := resolveNativeScanOptions(cmd, settings, opts); err != nil {
			t.Fatalf("resolveNativeScanOptions(%v): %v", args, err)
		}
		return opts, settings
	}

	t.Run("project overlay applies", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, overlayTestProject)
		opts, settings := resolve(t)
		if got := settings.Scope.Host.Include; !slices.Equal(got, []string{"app.example.com"}) {
			t.Fatalf("scope.host.include = %q, want the project's [app.example.com]", got)
		}
		if opts.Concurrency != 7 {
			t.Fatalf("concurrency = %d, want the project's scanning_pace 7", opts.Concurrency)
		}
		// A key the overlay does not set keeps its global value.
		if got := settings.Scope.Path.Include; !slices.Equal(got, config.DefaultSettings().Scope.Path.Include) {
			t.Fatalf("scope.path.include = %q, want the global value", got)
		}
	})

	t.Run("scanning profile outranks the project", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, overlayTestProject)
		_, settings := resolve(t, "--scanning-profile", "narrow")
		if got := settings.Scope.Host.Include; !slices.Equal(got, []string{"profile.example.com"}) {
			t.Fatalf("scope.host.include = %q, want the profile's [profile.example.com]", got)
		}
	})

	t.Run("CLI flag outranks the project", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, overlayTestProject)
		opts, _ := resolve(t, "--concurrency", "3")
		if opts.Concurrency != 3 {
			t.Fatalf("concurrency = %d, want the flag's 3", opts.Concurrency)
		}
	})

	t.Run("a project without an overlay is global-only", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, "")
		_, settings := resolve(t)
		if got := settings.Scope.Host.Include; !slices.Equal(got, globalInclude) {
			t.Fatalf("scope.host.include = %q, want the global %q", got, globalInclude)
		}
	})

	t.Run("the active project's overlay applies", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, "")
		if err := config.WriteActiveProject(overlayTestProject); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(config.ActiveProjectFilePath()) })
		_, settings := resolve(t)
		if got := settings.Scope.Host.Include; !slices.Equal(got, []string{"app.example.com"}) {
			t.Fatalf("scope.host.include = %q, want the active project's overlay", got)
		}
	})

	t.Run("a VIGOLIUM_DB_PATH pin is unscoped unless a project is named", func(t *testing.T) {
		if err := config.WriteActiveProject(overlayTestProject); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(config.ActiveProjectFilePath()) })
		swapGlobal(t, &dbPathEnvPinned, true)

		swapGlobal(t, &globalProjectUUID, "")
		_, settings := resolve(t)
		if got := settings.Scope.Host.Include; !slices.Equal(got, globalInclude) {
			t.Fatalf("pinned, no project named: scope.host.include = %q, want the global %q", got, globalInclude)
		}

		swapGlobal(t, &globalProjectUUID, overlayTestProject)
		_, settings = resolve(t)
		if got := settings.Scope.Host.Include; !slices.Equal(got, []string{"app.example.com"}) {
			t.Fatalf("pinned, project named: scope.host.include = %q, want the project's", got)
		}
	})

	t.Run("scan-url admission judges the project's scope", func(t *testing.T) {
		swapGlobal(t, &globalProjectUUID, overlayTestProject)
		swapGlobal(t, &scanIgnoreScope, false)
		swapGlobal(t, &globalConfig, "")
		clicommon.ResetProjectResolutionForTest()
		adm, err := admitDirectInputs(&directSettings{}, []scanInput{
			{target: "https://app.example.com/"},
			{target: "https://other.example.org/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, refused := adm.verdict("https://app.example.com/"); refused {
			t.Fatal("the project's own host was refused")
		}
		if _, refused := adm.verdict("https://other.example.org/"); !refused {
			t.Fatal("a host outside the project's scope.host.include was admitted")
		}
	})

	t.Run("a broken overlay is fatal", func(t *testing.T) {
		const broken = "0b0b0b0b-1111-2222-3333-444444444444"
		writeProjectOverlay(t, broken, "scope: [\n")
		swapGlobal(t, &globalProjectUUID, broken)
		clicommon.ResetProjectResolutionForTest()
		if _, err := loadProjectSettings(""); err == nil {
			t.Fatal("loadProjectSettings succeeded over an unparseable project overlay")
		}
	})
}
