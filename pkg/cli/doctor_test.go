package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func TestHighlightTipCommands(t *testing.T) {
	const tip = "install with `sudo apt install chromium` (or run `vigolium doctor --fix --only chrome` to download Chrome for Testing)"

	t.Run("color disabled keeps backticks unchanged", func(t *testing.T) {
		restore := terminal.IsColorEnabled()
		terminal.SetColorEnabled(false)
		defer terminal.SetColorEnabled(restore)

		if got := highlightTipCommands(tip); got != tip {
			t.Fatalf("expected tip unchanged when color disabled\n got: %q\nwant: %q", got, tip)
		}
	})

	t.Run("color enabled wraps commands in bold cyan", func(t *testing.T) {
		restore := terminal.IsColorEnabled()
		terminal.SetColorEnabled(true)
		defer terminal.SetColorEnabled(restore)

		got := highlightTipCommands(tip)

		// Both backtick-wrapped commands must be emitted in bold cyan.
		for _, cmd := range []string{"sudo apt install chromium", "vigolium doctor --fix --only chrome"} {
			if !strings.Contains(got, terminal.BoldCyan(cmd)) {
				t.Errorf("expected bold-cyan %q in output, got %q", cmd, got)
			}
		}
		// Backticks are dropped once the command is colorized.
		if strings.Contains(terminal.StripANSI(got), "`") {
			t.Errorf("expected backticks removed in colored output, got %q", terminal.StripANSI(got))
		}
		// Surrounding prose survives intact (sans backticks).
		plain := terminal.StripANSI(got)
		if !strings.Contains(plain, "install with ") || !strings.Contains(plain, " to download Chrome for Testing)") {
			t.Errorf("surrounding prose lost: %q", plain)
		}
	})
}

// doctor's exit status follows its verdict, after the report is written:
// not_ready exits 1 with error.code not_ready, degraded exits 1 only under
// --strict. Before, doctor always exited 0.
func TestDoctorExitFollowsVerdict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorOnly, nil)

	cases := []struct {
		status   diagnostics.Status
		strict   bool
		wantExit int
	}{
		{"not_ready", false, ExitError},
		{"not_ready", true, ExitError},
		{"degraded", false, ExitSuccess},
		{"degraded", true, ExitError},
		{"ready", true, ExitSuccess},
	}
	for _, tc := range cases {
		t.Run(string(tc.status)+fmt.Sprintf("/strict=%v", tc.strict), func(t *testing.T) {
			swapGlobal(t, &doctorStrict, tc.strict)
			swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report {
				return &diagnostics.Report{
					Status:   tc.status,
					Database: &diagnostics.CheckResult{Status: diagnostics.StatusError, Message: "injected"},
				}
			})
			jsonResultEmitted = false
			t.Cleanup(func() { jsonResultEmitted = false })

			var err error
			out := captureStdout(t, func() { err = runDoctorCmd(doctorCmd, nil) })
			if got := classifyExitCode(err); got != tc.wantExit {
				t.Fatalf("exit = %d (err %v), want %d", got, err, tc.wantExit)
			}
			if err != nil {
				if code := classifyErrorCode(err, classifyExitCode(err)); code != apicontract.CodeNotReady {
					t.Fatalf("error.code = %q, want not_ready", code)
				}
			}
			// The report is on stdout regardless of the exit status.
			if !strings.Contains(out, `"status":"`+string(tc.status)+`"`) && !strings.Contains(out, `"status": "`+string(tc.status)+`"`) {
				t.Fatalf("report not on stdout: %s", out)
			}
		})
	}
}
