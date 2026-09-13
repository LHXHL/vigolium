package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// buildGenFlagsFixture mirrors the shape that broke the real generator: a root
// with a persistent --format, a subcommand that REDEFINES --format with its own
// type/default/shorthand, a subcommand that only inherits it, a command with no
// flags at all, and a pass-through shim.
func buildGenFlagsFixture() *cobra.Command {
	root := &cobra.Command{Use: "vigolium", Short: "root"}
	var rootFormat string
	root.PersistentFlags().StringVar(&rootFormat, "format", "console", "Global output format")

	db := &cobra.Command{Use: "db", Short: "database"}
	export := &cobra.Command{Use: "export", Short: "Export database records"}
	var exportFormat string
	export.Flags().StringVarP(&exportFormat, "format", "f", "jsonl", "Export format: jsonl, json, raw, csv")
	db.AddCommand(export)

	// Inherits --format and adds nothing of its own.
	stats := &cobra.Command{Use: "stats", Short: "Show stats"}
	db.AddCommand(stats)

	// No flags, and its entire interface is positional.
	set := &cobra.Command{Use: "set <key> <value>", Short: "Set a configuration value"}

	traffic := &cobra.Command{Use: "traffic", Short: "Browse traffic", Aliases: []string{"tf", "traffics"}}

	shim := &cobra.Command{Use: "ffuf", Short: "ffuf-compatible", DisableFlagParsing: true}

	root.AddCommand(db, set, traffic, shim)
	return root
}

// The bug: subtractFlags removed a local flag whenever the ROOT had a flag of
// the same name, so `db export -f/--format` — the primary control of the
// command, with its own vocabulary and default — vanished from the reference
// entirely, along with roughly forty others across eighteen commands.
func TestLocalOverrideOfAGlobalFlagIsDocumented(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	section := sectionOf(t, doc, "## vigolium db export")
	if !strings.Contains(section, "`--format`") {
		t.Fatalf("db export --format was dropped:\n%s", section)
	}
	// The shorthand, the local default, and the local vocabulary are precisely
	// the information a reader needs and the name-based subtraction destroyed.
	if !strings.Contains(section, "`-f`") {
		t.Errorf("shorthand -f missing:\n%s", section)
	}
	if !strings.Contains(section, "`jsonl`") {
		t.Errorf("local default missing:\n%s", section)
	}
	if !strings.Contains(section, "overrides the global") {
		t.Errorf("an override must be labeled so it is not read as the global flag:\n%s", section)
	}
}

func TestInheritedFlagIsNotRepeatedPerCommand(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	// db stats only inherits --format; repeating it under every command would
	// triple the file for no new information.
	section := sectionOf(t, doc, "## vigolium db stats")
	if strings.Contains(section, "`--format`") {
		t.Errorf("a merely inherited flag should not be repeated:\n%s", section)
	}
	if !strings.Contains(doc, "## Global Flags") {
		t.Error("the global section must still exist")
	}
}

// Commands with no flags of their own used to be omitted entirely, which is how
// `config set`, `scope set`, `db reset`, `storage rm`, `kit wordlist` and 28
// other paths became undiscoverable to a reader of this file.
func TestCommandsWithNoLocalFlagsStillGetASection(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	for _, want := range []string{"## vigolium db stats", "## vigolium set", "## vigolium ffuf"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing section %q; a command with no flags is still part of the interface", want)
		}
	}
}

// For a command whose interface is entirely positional, the argument shape is
// the only thing worth printing, and a flag-table-only reference said nothing.
func TestPositionalArgumentShapeIsRendered(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	section := sectionOf(t, doc, "## vigolium set")
	if !strings.Contains(section, "vigolium set <key> <value>") {
		t.Errorf("positional arguments must be shown:\n%s", section)
	}
}

func TestAliasesAreRendered(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	section := sectionOf(t, doc, "## vigolium traffic")
	if !strings.Contains(section, "`tf`") || !strings.Contains(section, "`traffics`") {
		t.Errorf("aliases must be listed so an alias in a recipe is resolvable:\n%s", section)
	}
}

func TestPassThroughShimIsLabeled(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())

	section := sectionOf(t, doc, "## vigolium ffuf")
	if !strings.Contains(section, "Compatibility shim") {
		t.Errorf("a DisableFlagParsing command has no cobra flags; an empty table there "+
			"must not read as 'this command takes no flags':\n%s", section)
	}
}

func TestBareFlagsPlaceholderIsNotPrintedAsUsage(t *testing.T) {
	doc := renderFlagsReference(buildGenFlagsFixture())
	if strings.Contains(doc, "Usage: `vigolium db export`") {
		t.Error("a usage line with no positional arguments adds nothing and should be omitted")
	}
}

// sectionOf returns the text from heading up to the next "## " heading.
func sectionOf(t *testing.T, doc, heading string) string {
	t.Helper()
	i := strings.Index(doc, heading+"\n")
	if i < 0 {
		t.Fatalf("section %q not found in generated doc", heading)
	}
	rest := doc[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}
