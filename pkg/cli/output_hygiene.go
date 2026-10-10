package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Output hygiene: the global --color and --pretty flags.
//
// Color used to be forced ON for every command, TTY or not, so the -P fan-out's
// per-host console.log kept its color. The cost was that every pipe got escape
// codes too: `vigolium db stats 2>&1 >/dev/null | cat -v` was full of `^[[`.
// Now the default is auto (both streams must be terminals), and the -P parent
// asks its children for color explicitly with --color=always (childColorArgs).
//
// -j output used to be indented, which is the larger half of a document's bytes
// for no consumer that parses it. It is now compact by default; --pretty (or
// $VIGOLIUM_JSON_PRETTY=1) restores the indentation for a person reading it.

var (
	// globalColor backs --color auto|always|never.
	globalColor string
	// globalPretty backs --pretty: indent -j output.
	globalPretty bool
)

// jsonPrettyEnv lets a shell that reads -j output by eye turn indentation on
// for every command without editing each command line.
const jsonPrettyEnv = "VIGOLIUM_JSON_PRETTY"

// registerOutputHygieneFlags adds the persistent --color and --pretty flags.
// The env var is resolved once, as --pretty's default, the same rule the other
// env-backed flags follow: an explicit --pretty=false still wins, and Changed()
// keeps meaning "typed on the command line".
func registerOutputHygieneFlags(pf *pflag.FlagSet) {
	pf.StringVar(&globalColor, "color", string(terminal.ColorAuto),
		"Color ANSI output: auto (only when stdout and stderr are both terminals), always, or never. --no-color is never; NO_COLOR, FORCE_COLOR and CLICOLOR_FORCE are honored under auto. -j, --events and --ci-output-format force never")
	pf.BoolVar(&globalPretty, "pretty", envBool(jsonPrettyEnv),
		"Indent -j/--json output for reading (default: compact, one line). Also $VIGOLIUM_JSON_PRETTY=1. --watch stays one compact document per line")
}

// resolveColorMode folds --no-color into --color and validates the value.
// --no-color is kept as the spelling of never; combined with any other explicit
// mode it is a contradiction, not a precedence question.
func resolveColorMode(cmd *cobra.Command) (terminal.ColorMode, error) {
	mode, err := terminal.ParseColorMode(globalColor)
	if err != nil {
		return "", usageErrorf("%v", err)
	}
	if globalNoColor {
		if flagChanged(cmd, "color") && mode != terminal.ColorNever {
			return "", usageErrorf("--no-color contradicts --color=%s; pass one of them", mode)
		}
		return terminal.ColorNever, nil
	}
	return mode, nil
}

// colorMachineMode reports that this invocation's output is for a program:
// -j, --events or --ci-output-format. Color is forced off there, on stderr too,
// because a driver capturing both streams should not have to strip escape
// codes out of the notices.
func colorMachineMode() bool {
	return globalJSON || globalCIOutput || strings.TrimSpace(scanOpts.Events) != ""
}

// applyColorFlag sets the process color state from --color/--no-color.
func applyColorFlag(cmd *cobra.Command) error {
	mode, err := resolveColorMode(cmd)
	if err != nil {
		return err
	}
	terminal.ApplyColorMode(mode, colorMachineMode())
	return nil
}

// childColorArgs is what the -P parent adds to each child's argv so the child's
// captured <output>.console.log stays colored, which is the reason color used
// to be forced on everywhere. It adds nothing when the operator opted out
// (--color/--no-color typed, NO_COLOR, --ci-output-format) — childScanArgs
// already forwards a typed --color/--no-color, and the child inherits NO_COLOR
// from the environment, so the opt-out reaches every log.
func childColorArgs(cmd *cobra.Command) []string {
	if flagChanged(cmd, "color") || flagChanged(cmd, "no-color") || globalNoColor || globalCIOutput ||
		os.Getenv("NO_COLOR") != "" {
		return nil
	}
	return []string{"--color=always"}
}

// flagChanged reports whether name was typed on cmd's command line, local or
// inherited. A nil command (a unit test calling a helper directly) has none.
func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	f := cmd.Flags().Lookup(name)
	return f != nil && f.Changed
}

var legacyPrettyOnce sync.Once

// warnLegacyPretty is the deprecation path for the local --pretty that `replay`
// and `fuzz` used to have, with the opposite meaning: "human output instead of
// JSON". The name now belongs to the global flag that indents -j output, and
// human output is the default, so the old spelling is a no-op — except on bulk
// replay, which keeps its JSONL default for one more release and still reads
// it as a request for the per-record tables (bulk names the replacement there).
// It warns once, and only when --pretty was typed without -j, which is the old
// usage.
func warnLegacyPretty(cmd *cobra.Command, bulk bool) {
	if globalJSON || !flagChanged(cmd, "pretty") {
		return
	}
	legacyPrettyOnce.Do(func() {
		hint := "human output is now the default"
		if bulk {
			hint = "use --format console for the per-record tables (the default from the next release)"
		}
		fmt.Fprintf(os.Stderr, "%s %s --pretty is deprecated: %s. "+
			"--pretty only indents -j output; use -j for JSON and --format jsonl for the per-item stream\n",
			terminal.WarningSymbol(), commandPathWithoutRoot(cmd), hint)
	})
}

// requestedStreamFormat reads --format on a command whose only stream is a
// per-item JSONL (replay, fuzz): "" when not typed, else "console" (the human
// view) or "jsonl" (the stream). The stream owns stdout only when asked for by
// name. Any other format is a usage error rather than a silent fall-back to
// the default, since those commands render neither html nor sarif.
func requestedStreamFormat(cmd *cobra.Command) (string, error) {
	if !flagChanged(cmd, "format") {
		return "", nil
	}
	format := ""
	for _, f := range strings.Split(globalFormat, ",") {
		switch v := strings.ToLower(strings.TrimSpace(f)); v {
		case "jsonl", "console":
			if format != "" && format != v {
				return "", usageErrorf("%s takes one --format: console (the human view) or jsonl (the per-item stream)",
					commandPathWithoutRoot(cmd))
			}
			format = v
		case "":
		default:
			return "", usageErrorf("%s supports --format console (the human view, default) or jsonl (the per-item stream), not %q",
				commandPathWithoutRoot(cmd), strings.TrimSpace(f))
		}
	}
	return format, nil
}
