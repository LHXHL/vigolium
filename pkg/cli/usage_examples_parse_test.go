package cli

import (
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
//     That one parses fine and is still wrong, which is why the validator has a
//     semantic layer alongside the parse check.
//
// Every cobra Example and Long (and the skill bundle, README, docs/ and the
// --full-example tour) is now checked by doc_commands_test.go, which lexes
// pipes, substitutions and continuations instead of skipping those lines. The
// flag-set copy it parses against lives here.

// newParseFlagSet builds a COPY of cmd's flag set (local and inherited), so
// parsing a documented command records nothing on the shared command tree.
func newParseFlagSet(cmd *cobra.Command) *pflag.FlagSet {
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
	return fs
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
// consumes one). It records every value it was given, for the enum checks.
type noopFlagValue struct {
	typ string
	def string
	all []string
}

func (n *noopFlagValue) String() string { return n.def }
func (n *noopFlagValue) Set(s string) error {
	n.all = append(n.all, s)
	return nil
}
func (n *noopFlagValue) Type() string { return n.typ }
