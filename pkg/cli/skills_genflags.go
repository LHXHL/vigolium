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
}

// commandDoc is one section of the reference: a command and the flags it owns.
type commandDoc struct {
	Path  string // "vigolium agent swarm"
	Short string
	Flags []flagDoc
}

func renderFlagsReference(root *cobra.Command) string {
	globals := collectFlags(root.PersistentFlags())

	// Root's persistent flags are inherited everywhere; listing them under
	// each of ~60 subcommands would triple the file for no new information.
	// They get one section, and every other command lists only what it adds.
	var sections []commandDoc
	walkCommands(root, root.Name(), func(c *cobra.Command, path string) {
		flags := collectFlags(c.LocalFlags())
		flags = subtractFlags(flags, globals)
		if len(flags) == 0 {
			return
		}
		sections = append(sections, commandDoc{
			Path:  path,
			Short: c.Short,
			Flags: flags,
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
	writeFlagTable(&b, globals)

	for _, s := range sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s.Path)
		if s.Short != "" {
			b.WriteString(s.Short + "\n\n")
		}
		writeFlagTable(&b, s.Flags)
	}

	return b.String()
}

// walkCommands visits every non-hidden, runnable command depth-first, passing
// the full invocation path ("vigolium agent swarm").
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

func collectFlags(fs *pflag.FlagSet) []flagDoc {
	var out []flagDoc
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" {
			return
		}
		out = append(out, flagDoc{
			Name:        f.Name,
			Short:       f.Shorthand,
			Type:        f.Value.Type(),
			Default:     f.DefValue,
			Description: f.Usage,
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// subtractFlags drops any flag already documented in the global section.
func subtractFlags(flags, globals []flagDoc) []flagDoc {
	seen := make(map[string]struct{}, len(globals))
	for _, g := range globals {
		seen[g.Name] = struct{}{}
	}
	var out []flagDoc
	for _, f := range flags {
		if _, dup := seen[f.Name]; dup {
			continue
		}
		out = append(out, f)
	}
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
		short := "—"
		if f.Short != "" {
			short = "`-" + f.Short + "`"
		}
		def := "—"
		// A bare `""` default reads as "unset"; an em dash says that more
		// clearly than an empty cell, which looks like a rendering bug.
		if f.Default != "" && f.Default != "[]" && f.Default != "map[]" {
			def = "`" + f.Default + "`"
		}
		fmt.Fprintf(b, "| `--%s` | %s | %s | %s | %s |\n",
			f.Name, short, f.Type, def, escapeTableCell(f.Description))
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
