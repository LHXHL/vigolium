package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// stageCoreDeps runs a test against a throwaway HOME whose dependency check
// reports st, with an install that fails the test if anything calls it. It
// returns the marker path.
func stageCoreDeps(t *testing.T, st coreDepState) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	prevConfig := globalConfig
	globalConfig = ""
	t.Cleanup(func() { globalConfig = prevConfig })

	origCheck := checkCoreDeps
	checkCoreDeps = func(*config.Settings) coreDepState { return st }
	t.Cleanup(func() { checkCoreDeps = origCheck })

	origFix := runCoreDepFixes
	runCoreDepFixes = func(context.Context, *diagnostics.Report, *config.Settings, []string) []diagnostics.FixResult {
		t.Fatal("the scan bootstrap must never install dependencies (RunFixes called)")
		return nil
	}
	t.Cleanup(func() { runCoreDepFixes = origFix })

	return filepath.Join(home, ".vigolium", initMarkerFileName)
}

// TestEnsureCoreDepsMissingIsCheckOnly: on a cold HOME with chromium missing,
// the bootstrap installs nothing, leaves the marker unwritten (so the next run
// checks again) and says so in exactly one stderr line.
func TestEnsureCoreDepsMissingIsCheckOnly(t *testing.T) {
	marker := stageCoreDeps(t, coreDepState{chromeMissing: true})

	out := captureStderr(t, func() {
		if err := ensureCoreDeps(false); err != nil {
			t.Fatalf("ensureCoreDeps: %v", err)
		}
	})

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("marker written although chromium is missing")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one stderr line, got %d: %q", len(lines), out)
	}
	for _, want := range []string{"chromium not found", "first --spider", "~150 MB", "vigolium doctor --fix"} {
		if !strings.Contains(out, want) {
			t.Errorf("notice %q lacks %q", out, want)
		}
	}
}

// TestEnsureCoreDepsQuietPrintsNothing: under -j/--events/non-TTY the notice
// is suppressed (scan.setup carries the news), and still nothing installs.
func TestEnsureCoreDepsQuietPrintsNothing(t *testing.T) {
	marker := stageCoreDeps(t, coreDepState{chromeMissing: true, nucleiMissing: true})

	out := captureStderr(t, func() {
		if err := ensureCoreDeps(true); err != nil {
			t.Fatalf("ensureCoreDeps: %v", err)
		}
	})
	if out != "" {
		t.Fatalf("quiet bootstrap wrote to stderr: %q", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("marker written although deps are missing")
	}
}

// TestEnsureCoreDepsPresentStampsMarker: both present → marker, silently.
func TestEnsureCoreDepsPresentStampsMarker(t *testing.T) {
	marker := stageCoreDeps(t, coreDepState{})

	out := captureStderr(t, func() {
		if err := ensureCoreDeps(false); err != nil {
			t.Fatalf("ensureCoreDeps: %v", err)
		}
	})
	if out != "" {
		t.Fatalf("healthy bootstrap wrote to stderr: %q", out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker not written with both deps present: %v", err)
	}
}

func TestCoreDepNoticeWording(t *testing.T) {
	cases := map[coreDepState][]string{
		{nucleiMissing: true}:                      {"nuclei-templates not found", "known-issue scan"},
		{chromeMissing: true, nucleiMissing: true}: {"chromium and nuclei-templates not found", "~150 MB"},
	}
	for st, wants := range cases {
		got := st.notice()
		if strings.Contains(got, "\n") {
			t.Errorf("notice spans lines: %q", got)
		}
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("notice(%+v) = %q, lacks %q", st, got, w)
			}
		}
		if !strings.Contains(got, "vigolium doctor --fix") {
			t.Errorf("notice(%+v) = %q names no fix", st, got)
		}
	}
}

// TestCoreDepNoticeQuietModes: the notice is for a person at a terminal only.
func TestCoreDepNoticeQuietModes(t *testing.T) {
	prevTTY := terminal.StderrIsTerminal()
	t.Cleanup(func() { terminal.SetStderrIsTerminal(prevTTY) })
	prevJSON, prevSilent := globalJSON, globalSilent
	t.Cleanup(func() { globalJSON, globalSilent = prevJSON, prevSilent })
	globalJSON, globalSilent = false, false

	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "scan"}
		c.Flags().String("events", "", "")
		return c
	}

	terminal.SetStderrIsTerminal(true)
	if coreDepNoticeQuiet(newCmd()) {
		t.Error("interactive scan should print the notice")
	}

	terminal.SetStderrIsTerminal(false)
	if !coreDepNoticeQuiet(newCmd()) {
		t.Error("non-TTY stderr should suppress the notice")
	}

	terminal.SetStderrIsTerminal(true)
	ev := newCmd()
	_ = ev.Flags().Set("events", "ndjson")
	if !coreDepNoticeQuiet(ev) {
		t.Error("--events should suppress the notice")
	}

	globalJSON = true
	if !coreDepNoticeQuiet(newCmd()) {
		t.Error("-j should suppress the notice")
	}
}

// TestCoreDepCommandsSkipDirectPath: scan-url / scan-request no longer run the
// first-run check; the phases provision lazily.
func TestCoreDepCommandsSkipDirectPath(t *testing.T) {
	for _, path := range []string{"scan-url", "scan-request", "oast ingest", "extensions run"} {
		if needsCoreDeps(cmdAtPath(path)) {
			t.Errorf("%s runs the first-run dependency check", path)
		}
	}
	for _, path := range []string{"scan", "ingest", "agent swarm"} {
		if !needsCoreDeps(cmdAtPath(path)) {
			t.Errorf("%s should run the first-run dependency check", path)
		}
	}
}
