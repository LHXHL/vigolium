package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/selfupdate"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

const (
	// installScriptURL is the public, README-documented first-install path. It
	// is also the recovery path when an in-place update cannot run.
	installScriptURL = "https://vigolium.com/install.sh"

	nucleiTemplatesRepo = "https://github.com/projectdiscovery/nuclei-templates.git"

	// updateStepTimeout bounds each step (binary download / git). The
	// nuclei-templates repo is large, so this matches the 10m budget
	// knownissuescan uses for its first-time clone.
	updateStepTimeout = 10 * time.Minute
)

var (
	updateSkipBinary    bool
	updateSkipTemplates bool
	updateCheckOnly     bool
	updateDryRun        bool
	updateInstallDir    string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Vigolium and its nuclei templates to the latest version",
	Long: `Update replaces the running Vigolium binary with the latest signed release,
then refreshes the local nuclei-templates checkout used by the known-issue scan.

The binary update runs in process (no shell, no curl). It reads the release's
metadata.json, checksums.txt and checksums.txt.minisig from one release prefix
(` + selfupdate.DefaultBaseURL + `, or $` + selfupdate.EnvBaseURL + `),
verifies the minisign signature against the release keys built into this
binary, checks the archive's sha256, runs the new binary's ` + "`version --json`" + `,
and only then renames it over the running binary (symlinks resolved). Any
failed check leaves the current binary untouched.

  --check        report whether a newer release exists; change nothing
  --dry-run      resolve and verify the signed release and check the binary
                 is writable, but download and replace nothing
  --install-dir  install into this directory instead of replacing the running
                 binary (for example ~/.local/bin)

When the running binary's directory is not writable the update stops and says
so: re-run with sudo, or use --install-dir. Installations marked as
package-managed (and binaries run by the npm package or Homebrew) must upgrade
through that package manager; use --skip-binary to update only templates. The
install script (curl -fsSL ` + installScriptURL + ` | bash) remains the
first-install and recovery path.

Vigolium also checks npm for a newer release on startup (at most once per day)
and prints a notice when one is available. Set ` + envDisableUpdateCheck + `=1
to silence that check, or ` + envAutoUpdate + `=1 to have it update and re-exec
automatically. Auto-update only acts for a person at a terminal: it stays off
under -j, --events, --ci-output-format, when stdout or stderr is not a TTY,
for ` + "`server`" + `, and when CI or a coding-agent environment variable (CI,
VIGOLIUM_AGENT, CLAUDECODE, …) is set.`,
	RunE: runUpdateCmd,
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&updateSkipBinary, "skip-binary", false, "Only update nuclei templates; do not update the binary")
	updateCmd.Flags().BoolVar(&updateSkipTemplates, "skip-templates", false, "Only update the binary; do not refresh nuclei templates")
	updateCmd.Flags().BoolVar(&updateCheckOnly, "check", false, "Only report whether a newer release is available; download and change nothing")
	updateCmd.Flags().BoolVar(&updateDryRun, "dry-run", false, "Resolve and verify the signed release and check the binary is writable, but download and replace nothing")
	updateCmd.Flags().StringVar(&updateInstallDir, "install-dir", "", "Install the binary into this directory instead of replacing the running one (e.g. ~/.local/bin)")
}

// Step statuses. "ok" is the only one that changed something.
const (
	stepOK        = "ok"
	stepFailed    = "failed"
	stepSkipped   = "skipped"
	stepCurrent   = "current"   // already on the latest release
	stepAvailable = "available" // --check: a newer release exists
	stepPlanned   = "planned"   // --dry-run: would run
)

// updateStepResult is one item of the -j result.
type updateStepResult struct {
	Step    string `json:"step"`   // "binary" | "templates"
	Status  string `json:"status"` // ok | failed | skipped | current | available | planned
	Message string `json:"message,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Path    string `json:"path,omitempty"`
}

type updateOutput struct {
	Steps []updateStepResult `json:"steps"`
}

// changed reports whether any step did its work.
func (o updateOutput) changed() bool {
	for _, s := range o.Steps {
		if s.Status == stepOK {
			return true
		}
	}
	return false
}

// updateSay prints decorative/progress output to stdout, but stays silent under
// --json so stdout remains a single parseable JSON document.
func updateSay(format string, args ...any) {
	if globalJSON {
		return
	}
	fmt.Printf(format, args...)
}

func runUpdateCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if updateSkipBinary && updateSkipTemplates {
		return usageErrorf("--skip-binary and --skip-templates are mutually exclusive (nothing to do)")
	}
	if updateCheckOnly && updateDryRun {
		return usageErrorf("--check and --dry-run are mutually exclusive")
	}
	if updateSkipBinary && (updateCheckOnly || updateInstallDir != "") {
		return usageErrorf("--check and --install-dir apply to the binary; drop --skip-binary")
	}

	doBinary := !updateSkipBinary
	doTemplates := !updateSkipTemplates && !updateCheckOnly
	if updateInstallDir != "" {
		updateInstallDir = config.ExpandPath(updateInstallDir)
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}
	templatesDir := diagnostics.NucleiTemplatesDir(settings)

	verb := "will perform"
	switch {
	case updateCheckOnly:
		verb = "will check"
	case updateDryRun:
		verb = "dry run, would perform"
	}
	updateSay("%s %s:\n", terminal.BoldCyan("Vigolium update"), terminal.White(verb))
	if doBinary {
		where := "the running binary"
		if updateInstallDir != "" {
			where = config.ContractPath(updateInstallDir)
		}
		updateSay("  %s update %s to the latest signed release\n", terminal.InfoSymbol(), terminal.Gray(where))
	}
	if doTemplates {
		updateSay("  %s update nuclei templates at %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(templatesDir)))
	}

	var out updateOutput
	var firstErr error
	var bin selfupdate.Result

	if doBinary {
		updateSay("\n%s %s\n", terminal.BoldCyan(terminal.SymbolStart), terminal.White("Updating binary..."))
		step, res, berr := runBinaryUpdateStep()
		bin = res
		out.Steps = append(out.Steps, step)
		if berr != nil {
			firstErr = berr
			updateSay("%s binary update failed: %v\n", terminal.ErrorSymbol(), berr)
		} else {
			updateSay("%s %s\n", terminal.SuccessSymbol(), terminal.White(step.Message))
			if w := installDirPathWarning(step); w != "" {
				updateSay("%s %s\n", terminal.WarningSymbol(), terminal.Yellow(w))
			}
		}
	} else {
		out.Steps = append(out.Steps, updateStepResult{Step: "binary", Status: stepSkipped})
	}

	switch {
	case doTemplates && updateDryRun:
		msg := fmt.Sprintf("would update nuclei templates at %s", config.ContractPath(templatesDir))
		out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: stepPlanned, Message: msg})
		updateSay("%s %s\n", terminal.InfoSymbol(), terminal.White(msg))
	case doTemplates:
		updateSay("\n%s %s\n", terminal.BoldCyan(terminal.SymbolStart), terminal.White("Updating nuclei templates..."))
		if msg, terr := updateNucleiTemplates(templatesDir); terr != nil {
			out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: stepFailed, Message: terr.Error()})
			if firstErr == nil {
				firstErr = terr
			}
			updateSay("%s templates update failed: %v\n", terminal.ErrorSymbol(), terr)
		} else {
			out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: stepOK, Message: msg})
			updateSay("%s %s\n", terminal.SuccessSymbol(), terminal.White(msg))
		}
	default:
		out.Steps = append(out.Steps, updateStepResult{Step: "templates", Status: stepSkipped})
	}

	if globalJSON {
		action := "update"
		if updateCheckOnly {
			action = "check"
		}
		extra := map[string]any{}
		if doBinary {
			extra["from"] = bin.From
			extra["to"] = bin.To
			extra["path"] = bin.Path
			extra["update_available"] = bin.UpdateAvailable
		}
		// One document even when a step failed: it latches, so the error is
		// carried by the exit code rather than by a second (error) document.
		if err := emitMutation(cmd, "steps", mutationResult{
			Changed: out.changed(),
			Action:  action,
			DryRun:  updateDryRun,
			Items:   out.Steps,
			Extra:   extra,
		}); err != nil {
			return err
		}
	}

	return firstErr
}

// runBinaryUpdateStep runs the binary half of `vigolium update` for the
// current flags: --check, --dry-run or a real in-place update.
func runBinaryUpdateStep() (updateStepResult, selfupdate.Result, error) {
	step := updateStepResult{Step: "binary"}
	refusal := binaryUpdateRefusal(updateInstallDir != "")
	if refusal != nil && !updateCheckOnly {
		step.Status, step.Message = stepFailed, refusal.Error()
		return step, selfupdate.Result{}, refusal
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateStepTimeout)
	defer cancel()
	opts := selfupdate.Options{
		CurrentVersion: currentSemver(),
		InstallDir:     updateInstallDir,
		DryRun:         updateDryRun,
		Logf: func(format string, args ...any) {
			updateSay("  %s %s\n", terminal.Gray(terminal.SymbolDot), terminal.Gray(fmt.Sprintf(format, args...)))
		},
	}

	var res selfupdate.Result
	var err error
	if updateCheckOnly {
		res, err = selfupdate.Check(ctx, opts)
	} else {
		res, err = selfUpdate(ctx, opts)
	}
	step.From, step.To, step.Path = res.From, res.To, res.Path
	if err != nil {
		step.Status, step.Message = stepFailed, err.Error()
		return step, res, err
	}

	switch {
	case !res.UpdateAvailable:
		step.Status = stepCurrent
		step.Message = fmt.Sprintf("already up to date (%s; latest release %s)", res.From, res.To)
	case updateCheckOnly:
		step.Status = stepAvailable
		step.Message = fmt.Sprintf("%s → %s available; run `vigolium update`", res.From, res.To)
		if refusal != nil {
			step.Message = fmt.Sprintf("%s → %s available; %v", res.From, res.To, refusal)
		}
	case res.DryRun:
		step.Status = stepPlanned
		step.Message = fmt.Sprintf("would replace %s with %s (%s, sha256 %s, signature verified)", res.Path, res.To, res.Archive, res.SHA256)
	case res.Changed:
		step.Status = stepOK
		step.Message = fmt.Sprintf("updated %s → %s at %s", res.From, res.To, res.Path)
	default:
		step.Status = stepCurrent
		step.Message = fmt.Sprintf("already up to date (%s)", res.From)
	}
	return step, res, nil
}

// binaryUpdateRefusal returns why this installation must not update its own
// binary, or nil. Package-managed installs always refuse; binaries run by the
// npm package or Homebrew refuse an in-place replace but may install a
// standalone copy with --install-dir.
func binaryUpdateRefusal(installDir bool) error {
	if manager := managedPackageManager(); manager != "" {
		return fmt.Errorf("this installation is managed by %s; %s. Use `vigolium update --skip-binary` to update only templates",
			manager, packageManagerUpgrade(manager))
	}
	if installDir {
		return nil
	}
	exe, err := selfupdate.ResolveExecutable()
	if err != nil {
		return nil
	}
	switch selfManagedChannel(exe) {
	case "npm":
		return fmt.Errorf("this binary is run by the npm package (%s); upgrade with `npm install -g @vigolium/vigolium@latest`, "+
			"or pass --install-dir to install a standalone copy. Use `vigolium update --skip-binary` to update only templates", exe)
	case "Homebrew":
		return fmt.Errorf("this binary is managed by Homebrew (%s); upgrade with `brew upgrade vigolium`, "+
			"or pass --install-dir to install a standalone copy. Use `vigolium update --skip-binary` to update only templates", exe)
	}
	return nil
}

// selfManagedChannel recognizes binaries owned by a distribution channel that
// has no package-manager marker: the npm launcher unpacks the binary into
// <VIGOLIUM_HOME>/npm-bin/<version>/<platform>/, and Homebrew keeps it in its
// Cellar. Replacing either in place would desynchronize that channel.
func selfManagedChannel(exe string) string {
	p := filepath.ToSlash(filepath.Clean(exe))
	parts := strings.Split(p, "/")
	if n := len(parts); n >= 4 && parts[n-4] == "npm-bin" {
		return "npm"
	}
	if strings.Contains(p, "/node_modules/") {
		return "npm"
	}
	if strings.Contains(p, "/Cellar/") {
		return "Homebrew"
	}
	return ""
}

// installDirPathWarning warns when --install-dir wrote a binary that is not
// the one running, since the new copy is only picked up if its directory
// precedes the running one on PATH.
func installDirPathWarning(step updateStepResult) string {
	if updateInstallDir == "" || step.Status != stepOK || step.Path == "" {
		return ""
	}
	exe, err := selfupdate.ResolveExecutable()
	if err != nil || filepath.Clean(exe) == filepath.Clean(step.Path) {
		return ""
	}
	return fmt.Sprintf("the running binary is %s; make sure %s precedes it on PATH, or remove the old copy",
		exe, filepath.Dir(step.Path))
}

// updateNucleiTemplates refreshes the templates checkout in place when it is an
// existing git clone, clones it fresh when absent, and refuses to touch a path
// that exists but is not a git repository (it may hold user data).
//
// The codebase clones with --depth 1, so a plain `git pull` is unsafe; a
// shallow fetch followed by `reset --hard FETCH_HEAD` is the robust shallow
// update and does not depend on knowing the default branch name.
func updateNucleiTemplates(dir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), updateStepTimeout)
	defer cancel()

	info, err := os.Stat(dir)
	switch {
	case err == nil && info.IsDir():
		if gi, gerr := os.Stat(filepath.Join(dir, ".git")); gerr != nil || !gi.IsDir() {
			return "", fmt.Errorf("%s exists but is not a git repository; remove it (or point known_issue_scan.templates_dir elsewhere) and re-run", config.ContractPath(dir))
		}
		if e := runGit(ctx, dir, "fetch", "--quiet", "--depth", "1", "origin"); e != nil {
			return "", fmt.Errorf("git fetch failed: %w", e)
		}
		if e := runGit(ctx, dir, "reset", "--quiet", "--hard", "FETCH_HEAD"); e != nil {
			return "", fmt.Errorf("git reset failed: %w", e)
		}
		return fmt.Sprintf("nuclei templates updated at %s", config.ContractPath(dir)), nil
	case err == nil && !info.IsDir():
		return "", fmt.Errorf("%s exists but is not a directory", config.ContractPath(dir))
	case os.IsNotExist(err):
		if e := runGit(ctx, "", "clone", "--quiet", "--depth", "1", nucleiTemplatesRepo, dir); e != nil {
			return "", fmt.Errorf("git clone failed: %w", e)
		}
		return fmt.Sprintf("nuclei templates cloned to %s", config.ContractPath(dir)), nil
	default:
		return "", fmt.Errorf("cannot stat %s: %w", config.ContractPath(dir), err)
	}
}

// runGit runs git with output wired to stderr. When dir is non-empty it is
// passed via -C so the command operates on that working tree.
func runGit(ctx context.Context, dir string, args ...string) error {
	full := args
	if dir != "" {
		full = append([]string{"-C", dir}, args...)
	}
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
