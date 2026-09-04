package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// ambiguousRunPhase rejects a phase name that collides with a top-level
// vigolium command, where `vigolium run <name>` reads as "run the <name>"
// rather than "run the <name> phase".
//
// Only "audit" collides today: it is an alias for the dynamic-assessment
// phase (native module scanning) and also the name of the AI source-code
// audit command, so `vigolium run audit` silently starts a full native
// scan when the operator asked for the audit.
//
// The alias itself stays valid everywhere else. `--only audit` and
// `--skip audit` are unambiguous because those flags only ever accept
// phases, so this guard is scoped to the positional form.
func ambiguousRunPhase(phase string) error {
	if !strings.EqualFold(strings.TrimSpace(phase), "audit") {
		return nil
	}
	return fmt.Errorf(`"audit" is ambiguous as a phase name:
  native module scan     -> vigolium run dynamic-assessment   (or: dast)
  AI source-code audit   -> vigolium agent audit

("--only audit" and "--skip audit" are unaffected)`)
}

// isDiscoveryPhaseArg reports whether the given `vigolium run <phase>` arg
// refers to the discovery or spidering phase (including aliases).
func isDiscoveryPhaseArg(phase string) bool {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "discover", "discovery", "deparos",
		"spidering", "spitolas":
		return true
	}
	return false
}

// isDiscoveryOnlyPhases reports whether every phase in a comma-separated
// --only value refers to discovery or spidering. Used to credit the
// discovery co-authors in the scan banner.
func isDiscoveryOnlyPhases(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	for _, p := range strings.Split(raw, ",") {
		if !isDiscoveryPhaseArg(p) {
			return false
		}
	}
	return true
}

var runCmd = &cobra.Command{
	Use:   "run <phase>",
	Short: "Run a single native scan phase (alias for scan --only <phase>)",
	Long: `Run a single scan phase directly. Equivalent to "vigolium scan --only <phase>".

Valid phases: ingestion, discovery (deparos), external-harvest, spidering (spitolas), known-issue-scan (cve, kis), dynamic-assessment (dast, assessment), extension (ext)`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"r"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ambiguousRunPhase(args[0]); err != nil {
			return err
		}
		globalOnly = args[0]
		// The positional arg is the phase name, not a target — pass nil so
		// runScanCmd does not merge it into the scan target list.
		return runScanCmd(cmd, nil)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	flags := runCmd.Flags()
	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerScanPipelineFlags(flags)
	registerSpecFlags(flags)
	registerNativeScanFlags(flags, true)
	addFlagAliases(runCmd, map[string]string{
		"fuzz-wordlist": "discovery-wordlist",
		"templates-dir": "known-issue-scan-templates-dir",
	})
}
