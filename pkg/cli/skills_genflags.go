package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The skill's flag reference used to be maintained by hand, in parallel with
// the cobra definitions it described. It drifted: shorthands went missing,
// defaults from one command leaked into another command's table, and nothing
// caught it because prose has no compiler. This generator walks the live
// command tree instead, so the document is a projection of the binary rather
// than a second source of truth.
//
//	make skill-flags
//
// The output path is committed so the skill bundle stays self-contained for
// consumers who only ever see the embedded copy.

// genFlagsDefaultOut is the committed location of the generated reference,
// relative to the repository root.
const genFlagsDefaultOut = "public/skills/vigolium-scanner/references/flags.generated.md"

var genFlagsOut string

// Subcommand: vigolium skills gen-flags
//
// Hidden because it is a repo maintenance tool, not an operator command — but
// it lives on the shipped binary deliberately: anyone can regenerate a flag
// reference that matches the exact version they have installed.
var skillsGenFlagsCmd = &cobra.Command{
	Use:    "gen-flags",
	Short:  "Regenerate the skill's flag reference from the command tree",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSkillsGenFlags(cmd.Root())
	},
}

func init() {
	skillsCmd.AddCommand(skillsGenFlagsCmd)
	skillsGenFlagsCmd.Flags().StringVarP(&genFlagsOut, "out", "o", genFlagsDefaultOut,
		"Destination file, or - for stdout")
}

func runSkillsGenFlags(root *cobra.Command) error {
	doc := renderFlagsReference(root)

	if genFlagsOut == "-" {
		fmt.Print(doc)
		return nil
	}
	if dir := filepath.Dir(genFlagsOut); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}
	if err := os.WriteFile(genFlagsOut, []byte(doc), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", genFlagsOut, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", genFlagsOut)
	return nil
}

// flagDoc is one row of a rendered table.
type flagDoc struct {
	Name        string
	Short       string
	Type        string
	Default     string
	Description string
	// Overrides marks a local flag whose NAME collides with a root persistent
	// flag but which is a different flag with its own type, default, and
	// vocabulary. `db export --format` (jsonl|json|raw|csv|markdown|bundle|fs,
	// default jsonl, shorthand -f) is not the root --format, and a reader who
	// assumes it is will pass a value the command rejects.
	Overrides bool
}

// commandDoc is one section of the reference: a command and the flags it owns.
type commandDoc struct {
	Path    string // "vigolium agent swarm"
	Use     string // "export [flags]" — carries the positional-argument shape
	Short   string
	Aliases []string
	// PassThrough marks a compatibility shim (ffuf, nuclei, katana, gau, arjun)
	// that parses another tool's argv itself. Its flags are that tool's, not
	// cobra's, so an empty table there means "not described here", not "none".
	PassThrough bool
	Flags       []flagDoc
}

func renderFlagsReference(root *cobra.Command) string {
	globalNames := flagNameSet(root.PersistentFlags())
	globals := collectFlags(root.PersistentFlags(), nil)

	// Root's persistent flags are inherited everywhere; listing them under
	// each of ~60 subcommands would triple the file for no new information.
	// They get one section, and every other command lists only what it adds.
	var sections []commandDoc
	walkCommands(root, root.Name(), func(c *cobra.Command, path string) {
		flags := collectFlags(c.LocalFlags(), globalNames)
		// A command with no flags of its own is still part of the interface.
		// Dropping it here is how `config set`, `scope set`, `db reset`,
		// `storage rm`, `kit wordlist`, and 28 other command paths became
		// invisible to anyone reading this file to find out what exists — the
		// reference described 67 of the 100 command paths and said nothing
		// about the gap. The section is emitted regardless; the table says
		// "no command-specific flags" and the heading still carries the
		// positional-argument shape, which for `config set <key> <value>` is
		// the entire interface.
		sections = append(sections, commandDoc{
			Path:        path,
			Use:         c.Use,
			Short:       c.Short,
			Aliases:     c.Aliases,
			PassThrough: c.DisableFlagParsing,
			Flags:       flags,
		})
	})
	sort.SliceStable(sections, func(i, j int) bool { return sections[i].Path < sections[j].Path })

	var b strings.Builder
	b.WriteString("# Flag Reference (generated)\n\n")
	b.WriteString("<!-- GENERATED FILE — DO NOT EDIT BY HAND.\n")
	b.WriteString("     Regenerate with `make skill-flags` (or `vigolium skills gen-flags`).\n")
	b.WriteString("     Every row below is read straight off the cobra command tree, so it\n")
	b.WriteString("     always matches the binary that produced it. -->\n\n")
	b.WriteString("Every flag on every command, grouped by the command that owns it.\n")
	b.WriteString("**Global flags are listed once** and are available everywhere; each command\n")
	b.WriteString("section lists only the flags that command adds.\n\n")
	b.WriteString("This file is for lookup — grep it for a flag name rather than reading it\n")
	b.WriteString("top to bottom. For the authoritative help of the version you have installed,\n")
	b.WriteString("run `vigolium <command> -h`.\n\n")

	// Table of contents.
	b.WriteString("## Contents\n\n")
	b.WriteString("- [Global Flags](#global-flags)\n")
	for _, s := range sections {
		fmt.Fprintf(&b, "- [%s](#%s)\n", s.Path, anchorize(s.Path))
	}
	b.WriteString("\n---\n\n")

	b.WriteString("## Global Flags\n\n")
	b.WriteString("Persistent flags available on every command.\n\n")
	b.WriteString("A command section below may redefine one of these names with a different\n")
	b.WriteString("type, default, or set of accepted values. Such a row is marked **overrides**\n")
	b.WriteString("and wins for that command — read it instead of the row here.\n\n")
	writeFlagTable(&b, globals)

	for _, s := range sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s.Path)
		if usage := positionalUsage(s); usage != "" {
			fmt.Fprintf(&b, "Usage: `%s`\n\n", usage)
		}
		if len(s.Aliases) > 0 {
			fmt.Fprintf(&b, "Aliases: %s\n\n", backtickList(s.Aliases))
		}
		if s.Short != "" {
			b.WriteString(s.Short + "\n\n")
		}
		if s.PassThrough {
			b.WriteString("**Compatibility shim.** This command parses another tool's argv itself " +
				"rather than through cobra, so it accepts that tool's flags, not the ones listed here. " +
				"It is a subset: run it with `-h` for what is actually translated.\n\n")
		}
		writeFlagTable(&b, s.Flags)
	}

	return b.String()
}

// positionalUsage renders the full invocation including positional arguments.
// For a command with no flags of its own — `config set <key> <value>`,
// `storage rm <key>...`, `project create [name]` — the argument shape IS the
// interface, and a reference that prints only flag tables says nothing at all
// about it.
func positionalUsage(s commandDoc) string {
	use := strings.TrimSpace(s.Use)
	name := s.Path[strings.LastIndex(s.Path, " ")+1:]
	args := strings.TrimSpace(strings.TrimPrefix(use, name))
	// A bare "[flags]" says nothing the table below does not; the line is worth
	// printing only when it names actual positional arguments.
	args = strings.TrimSpace(strings.ReplaceAll(args, "[flags]", ""))
	if args == "" {
		return ""
	}
	return s.Path + " " + args
}

// backtickList renders names as inline code, comma-separated.
func backtickList(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, "`"+n+"`")
	}
	return strings.Join(out, ", ")
}

// walkCommands visits every non-hidden command depth-first, passing the full
// invocation path ("vigolium agent swarm").
//
// `help` and `completion` are skipped because cobra generates them and their
// interface is cobra's, not vigolium's. Everything else is visited, including
// commands with no flags of their own: a parent that only prints help is still
// part of the surface a caller has to discover.
func walkCommands(c *cobra.Command, path string, fn func(*cobra.Command, string)) {
	for _, child := range c.Commands() {
		if child.Hidden || child.Name() == "help" || child.Name() == "completion" {
			continue
		}
		childPath := path + " " + child.Name()
		fn(child, childPath)
		walkCommands(child, childPath, fn)
	}
}

// collectFlags renders a flagset's rows. globalNames marks a local flag whose
// name shadows a root persistent flag, so the table can say so; pass nil when
// rendering the root's own flags.
//
// Inheritance needs no filtering here: cobra's LocalFlags() already excludes a
// flag it merely inherits, comparing POINTERS against the parent flagsets
// (command.go: `f != c.parentsPflags.Lookup(f.Name)`), so a command that
// registers its own --format keeps it and one that only inherits --format does
// not. The bug this replaced was a by-NAME subtraction layered on top of that,
// which deleted `db export -f/--format` and roughly forty other genuine local
// flags across eighteen commands for colliding with a root name.
func collectFlags(fs *pflag.FlagSet, globalNames map[string]struct{}) []flagDoc {
	var out []flagDoc
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" {
			return
		}
		_, shadows := globalNames[f.Name]
		out = append(out, flagDoc{
			Name:        f.Name,
			Short:       f.Shorthand,
			Type:        f.Value.Type(),
			Default:     f.DefValue,
			Description: f.Usage,
			Overrides:   shadows,
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// flagNameSet indexes a flagset by name, for detecting a local override.
//
// It applies the same hidden/deprecated filter collectFlags does. Without that,
// a local flag shadowing a HIDDEN root flag (--stateless is hidden at root) got
// tagged "overrides the global --stateless" and sent the reader to look for a
// row in the global table that is deliberately not printed there.
func flagNameSet(fs *pflag.FlagSet) map[string]struct{} {
	out := map[string]struct{}{}
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" {
			return
		}
		out[f.Name] = struct{}{}
	})
	return out
}

func writeFlagTable(b *strings.Builder, flags []flagDoc) {
	if len(flags) == 0 {
		b.WriteString("_No command-specific flags._\n")
		return
	}
	b.WriteString("| Flag | Short | Type | Default | Description |\n")
	b.WriteString("|------|-------|------|---------|-------------|\n")
	for _, f := range flags {
		short := "-"
		if f.Short != "" {
			short = "`-" + f.Short + "`"
		}
		def := "-"
		// A bare `""` default reads as "unset"; a dash says that more clearly
		// than an empty cell, which looks like a rendering bug.
		if f.Default != "" && f.Default != "[]" && f.Default != "map[]" {
			def = "`" + f.Default + "`"
		}
		desc := escapeTableCell(f.Description)
		if f.Overrides {
			desc = "**(overrides the global `--" + f.Name + "`)** " + desc
		}
		fmt.Fprintf(b, "| `--%s` | %s | %s | %s | %s |\n",
			f.Name, short, f.Type, def, desc)
	}
}

// escapeTableCell makes usage strings safe for a markdown table: pipes would
// end the cell early and newlines would end the row.
func escapeTableCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

// anchorize mirrors GitHub's heading-slug rules closely enough for the TOC
// links in this file (lowercase, spaces to hyphens, drop other punctuation).
func anchorize(s string) string {
	var b bytes.Buffer
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-':
			b.WriteByte('-')
		}
	}
	return b.String()
}
