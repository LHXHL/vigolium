package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scopeSetProject string

var scopeSetCmd = &cobra.Command{
	Use:   "set <component.field> <value>",
	Short: "Set a scope rule",
	Long: "Set a scope rule using component.field notation (e.g. host.exclude \"*.internal.com,admin.*\").\n\n" +
		"Lists take the comma form or JSON/YAML flow syntax ('[\"*.example.com\",\"example.com\"]'); '<rule>.add <value>' " +
		"appends and '<rule>.clear' empties. The value is checked with the same rules as 'config validate' and refused " +
		"(exit 2, nothing written) when it would break the scope. Writes the global config, or with --project the " +
		"project's overlay (~/.vigolium/projects/<uuid>/config.yaml). A config that fails to load is never overwritten.",
	Args: cobra.ExactArgs(2),
	RunE: runScopeSet,
}

func init() {
	scopeSetCmd.Flags().StringVar(&scopeSetProject, "project", "", "Write the rule to this project's config overlay instead of the global config")
	scopeCmd.AddCommand(scopeSetCmd)
}

func runScopeSet(cmd *cobra.Command, args []string) error {
	key := "scope." + args[0]
	value := args[1]

	// config.LoadSettings*, not clicommon.LoadSettings: the CLI loader answers a
	// discovered-but-unreadable config with built-in defaults, and saving those
	// back would replace the operator's file with them. Refuse instead.
	settings, err := config.LoadSettingsWithProject(globalConfig, scopeSetProject)
	if err != nil {
		return fmt.Errorf("failed to load config, refusing to write: %w", err)
	}

	if err := config.SetField(settings, key, value); err != nil {
		if errors.Is(err, config.ErrUnknownKey) || errors.Is(err, config.ErrInvalidValue) {
			return clicommon.AsUsageError(fmt.Errorf("failed to set %q: %w", key, err))
		}
		return fmt.Errorf("failed to set %q: %w", key, err)
	}

	where := ""
	if scopeSetProject != "" {
		path, err := config.SetProjectOverlayValue(scopeSetProject, key, settings)
		if err != nil {
			if errors.Is(err, config.ErrUnknownKey) {
				return clicommon.AsUsageError(err)
			}
			return fmt.Errorf("failed to save project config: %w", err)
		}
		where = " (" + config.ContractPath(path) + ")"
	} else if err := config.SaveSettings(effectiveConfigPath(), settings); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("%s Set %s = %s%s\n", terminal.SuccessSymbol(), terminal.Cyan(key), value, terminal.Gray(where))
	return nil
}
