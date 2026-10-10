package configcmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// defaultRecentScans is how many recent scans' targets the
// scope_include_matches_no_recent_target rule checks by default.
const defaultRecentScans = 5

type validateOptions struct {
	Project string
	Recent  int
	Strict  bool
}

func newValidateCmd(deps Deps, example string) *cobra.Command {
	var opts validateOptions
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the configuration for values that break or silently weaken scans",
		Long: "Validate the effective configuration (global config, plus a project's overlay with --project) with the same rules " +
			"`config set` and `scope set` enforce and doctor's Scope check reports: malformed scope patterns, host patterns " +
			"with a scheme, path or port, an exact-host include that drops every subdomain, invalid status-code patterns, " +
			"origin modes and body actions, OAST settings, each section's own checks, and keys the config file sets that " +
			"vigolium does not recognise.\n\n" +
			"With a database available, a wildcard-free scope.host.include is also checked against the targets of the last " +
			"--recent scans. Exits 1 (error.code config_invalid) when any error-level issue is found; --strict also fails on warnings.",
		Example: example,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigValidate(cmd, deps, opts)
		},
	}
	cmd.Flags().StringVar(&opts.Project, "project", "", "Also validate this project's config overlay, checking the merged global → project settings")
	cmd.Flags().IntVar(&opts.Recent, "recent", defaultRecentScans, "Check a wildcard-free scope.host.include against the targets of the last N scans (0 disables)")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "Exit 1 on warnings as well as errors")
	return cmd
}

func runConfigValidate(cmd *cobra.Command, deps Deps, opts validateOptions) error {
	if opts.Recent < 0 {
		return clicommon.UsageErrorf("--recent must be >= 0, got %d", opts.Recent)
	}
	configFlag := ""
	if deps.ConfigFlag != nil {
		configFlag = deps.ConfigFlag()
	}
	configPath := clicommon.EffectiveConfigPath(configFlag)

	issues := []config.Issue{}
	settings, err := config.LoadSettingsWithProject(configFlag, opts.Project)
	if err != nil {
		// Reported as an issue, not returned: saying what is wrong with the
		// config is this command's whole job, and a load failure is the worst
		// thing that can be wrong with it.
		issues = append(issues, config.Issue{
			Severity: config.SeverityError,
			Code:     config.IssueConfigLoadFailed,
			Message:  err.Error(),
			Fix:      "fix the file named above (every other command refuses or ignores it until then)",
		})
	} else {
		issues = append(issues, config.ValidateConfigFile(configPath, &config.Settings{})...)
		if opts.Project != "" {
			issues = append(issues, config.ValidateConfigFile(config.ProjectConfigPath(opts.Project), &config.ProfileSettings{})...)
		}
		issues = append(issues, config.ValidateSettings(settings)...)
		// The DB-aware rule. A missing or unreadable database skips it: this
		// command validates configuration, and has no store to complain about.
		if opts.Recent > 0 && deps.RecentScanTargets != nil {
			if targets, err := deps.RecentScanTargets(opts.Project, opts.Recent); err == nil {
				issues = append(issues, config.ValidateRecentTargets(settings.Scope, targets)...)
			}
		}
	}

	var nErr, nWarn int
	for _, is := range issues {
		if is.Severity == config.SeverityError {
			nErr++
		} else {
			nWarn++
		}
	}
	failed := nErr > 0 || (opts.Strict && nWarn > 0)

	if deps.jsonRequested() {
		extra := map[string]any{
			"valid":       !failed,
			"errors":      nErr,
			"warnings":    nWarn,
			"strict":      opts.Strict,
			"config_path": config.ContractPath(configPath),
		}
		if opts.Project != "" {
			extra["project_config_path"] = config.ContractPath(config.ProjectConfigPath(opts.Project))
		}
		if err := deps.WriteJSON(cmd, "", issues, len(issues), extra); err != nil {
			return err
		}
	} else {
		printValidateReport(issues, configPath, opts)
	}

	switch {
	case nErr > 0:
		return clicommon.CodedErrorf(apicontract.CodeConfigInvalid,
			"config validation found %d error(s) and %d warning(s)", nErr, nWarn)
	case failed:
		return clicommon.CodedErrorf(apicontract.CodeConfigInvalid,
			"config validation found %d warning(s) (--strict)", nWarn)
	}
	return nil
}

func printValidateReport(issues []config.Issue, configPath string, opts validateOptions) {
	fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(configPath)))
	if opts.Project != "" {
		fmt.Printf("%s Project config: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(config.ProjectConfigPath(opts.Project))))
	}
	if len(issues) == 0 {
		fmt.Printf("%s No issues found\n", terminal.SuccessSymbol())
		return
	}
	for _, is := range issues {
		label := terminal.Yellow("warning")
		if is.Severity == config.SeverityError {
			label = terminal.Red("error  ")
		}
		fmt.Printf("  %s %s %s\n", label, terminal.Cyan(is.Code), is.Message)
		if is.Fix != "" {
			fmt.Printf("          %s %s\n", terminal.Gray("fix:"), is.Fix)
		}
	}
}
