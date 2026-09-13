package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// The bundled examples are the first thing an operator or an agent copies, and
// nothing checked that they still parse. They rotted quietly:
//
//   - `-F` appeared in eleven examples and had not been a registered shorthand
//     for some time; every one of them exited 2 with "unknown shorthand flag".
//   - `config ls --force` was documented as the way to reveal secrets, but the
//     reveal moved to the purpose-specific --show-secrets and --force stopped
//     doing anything there.
//   - `scan -T openapi.yaml -I openapi` passed a SPEC to the target-LIST flag.
//     That one parses fine and is still wrong, which is why the semantic check
//     below exists alongside the parse check.
//
// This test walks the real command tree and parses every example against the
// command it names, with execution disabled. It catches a flag that was renamed
// or removed the moment the example stops being valid.

func TestBundledExamplesParse(t *testing.T) {
	for _, ex := range collectExamples(t) {
		t.Run(ex.line, func(t *testing.T) {
			if err := parseExample(rootCmd, ex.argv); err != nil {
				t.Errorf("example on %s does not parse:\n  %s\n  %v", ex.command, ex.line, err)
			}
		})
	}
}

// A spec (OpenAPI/Swagger/WSDL/HAR/Burp export) is passed with -i/--input.
// -T/--target-file is a list of target URLs, one per line. Handing a spec to -T
// parses cleanly and then reads the YAML as if every line were a URL, so only a
// semantic check finds it.
func TestExamplesDoNotPassSpecsToTheTargetListFlag(t *testing.T) {
	specSuffixes := []string{".yaml", ".yml", ".json", ".wsdl", ".har", ".xml"}

	for _, ex := range collectExamples(t) {
		for i, arg := range ex.argv {
			if arg != "-T" && arg != "--target-file" {
				continue
			}
			if i+1 >= len(ex.argv) {
				continue
			}
			value := strings.ToLower(ex.argv[i+1])
			for _, suffix := range specSuffixes {
				if strings.HasSuffix(value, suffix) {
					t.Errorf("example passes a spec to the target-list flag; use -i/--input:\n  %s", ex.line)
				}
			}
		}
	}
}

type exampleLine struct {
	command string
	line    string
	argv    []string
}

// collectExamples walks the command tree and returns every runnable example
// line, with the leading "vigolium" stripped.
func collectExamples(t *testing.T) []exampleLine {
	t.Helper()

	var out []exampleLine
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, raw := range strings.Split(terminal.StripANSI(c.Example), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Examples that compose with a shell (pipes, redirection, command
			// substitution, continuations) are not a single argv and cannot be
			// parsed by cobra; they are out of scope for this check.
			if strings.ContainsAny(line, "|><$`\\") {
				continue
			}
			fields, ok := splitExampleArgv(line)
			if !ok || len(fields) == 0 || fields[0] != "vigolium" {
				continue
			}
			out = append(out, exampleLine{
				command: c.CommandPath(),
				line:    line,
				argv:    fields[1:],
			})
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)

	if len(out) == 0 {
		t.Fatal("no examples collected; the walk is broken, not the examples")
	}
	return out
}

// parseExample resolves argv to a command and parses its flags WITHOUT running
// it. Positional-argument validation is skipped: many examples use placeholders
// (<uuid>, <name>) that are not real values, and the flag surface is what rots.
func parseExample(root *cobra.Command, argv []string) error {
	cmd, remaining, err := root.Find(argv)
	if err != nil {
		return err
	}
	// A compatibility shim parses another tool's argv itself; cobra's flag set
	// says nothing about what it accepts.
	if cmd.DisableFlagParsing {
		return nil
	}

	// Parse against a COPY of the flag set so the real command's flag values and
	// Changed bits are not mutated for the rest of the test binary.
	fs := pflag.NewFlagSet(cmd.Name(), pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	// Several commands register normalized aliases (--caido-bridge-url for
	// --burp-bridge-url, --no-response for --omit-response). Without the
	// command's own normalizer the copy rejects spellings the real binary
	// accepts, and the test would report working examples as broken.
	if nf := cmd.Flags().GetNormalizeFunc(); nf != nil {
		fs.SetNormalizeFunc(nf)
	}
	cmd.Flags().VisitAll(func(f *pflag.Flag) { fs.AddFlag(copyFlagForParse(f)) })
	cmd.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		if fs.Lookup(f.Name) == nil {
			fs.AddFlag(copyFlagForParse(f))
		}
	})
	return fs.Parse(remaining)
}

// copyFlagForParse clones a flag with a throwaway value, so parsing an example
// records nothing on the shared command tree.
func copyFlagForParse(f *pflag.Flag) *pflag.Flag {
	return &pflag.Flag{
		Name:        f.Name,
		Shorthand:   f.Shorthand,
		Usage:       f.Usage,
		Value:       &noopFlagValue{typ: f.Value.Type(), def: f.DefValue},
		DefValue:    f.DefValue,
		NoOptDefVal: f.NoOptDefVal,
		Hidden:      f.Hidden,
	}
}

// noopFlagValue accepts any value and keeps the flag's own type, so pflag still
// applies the right arity rule (a bool consumes no argument; everything else
// consumes one).
type noopFlagValue struct {
	typ string
	def string
	set string
}

func (n *noopFlagValue) String() string { return n.def }
func (n *noopFlagValue) Set(s string) error {
	n.set = s
	return nil
}
func (n *noopFlagValue) Type() string { return n.typ }

// splitExampleArgv splits an example line into argv, honoring single and double
// quotes. An example like
//
//	vigolium replay -i "curl -X POST https://example.invalid -d 'u=admin'"
//
// is ONE argument after -i; splitting on whitespace would hand cobra a -X it was
// never given. Returns ok=false for an unterminated quote, which is a malformed
// example rather than a parse failure to report.
func splitExampleArgv(line string) (argv []string, ok bool) {
	var cur strings.Builder
	var quote rune
	started := false

	flush := func() {
		if started {
			argv = append(argv, cur.String())
			cur.Reset()
			started = false
		}
	}

	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return argv, true
}
