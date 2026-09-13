package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// The old gate read raw argv: hasFlag compared whole arguments (so --json=true
// slipped through), isSubcommand looked only at os.Args[1] (so an alias, a
// global placed first, or a nested path slipped through), and the exclusion list
// was hand-maintained (so every command nobody remembered got a banner welded to
// its stdout). These cases pin the replacement: the decision is made from the
// resolved cobra command, and the output goes to stderr regardless.
func TestCommandWantsBanner(t *testing.T) {
	root := &cobra.Command{Use: "vigolium"}
	completion := &cobra.Command{Use: "completion"}
	bash := &cobra.Command{Use: "bash"}
	completion.AddCommand(bash)
	root.AddCommand(completion)

	version := &cobra.Command{Use: "version"}
	traffic := &cobra.Command{Use: "traffic", Aliases: []string{"tf", "traffics"}}
	scan := &cobra.Command{Use: "scan"}
	dbCmd := &cobra.Command{Use: "db"}
	dbExport := &cobra.Command{Use: "export"}
	dbCmd.AddCommand(dbExport)
	root.AddCommand(version, traffic, scan, dbCmd)

	cases := []struct {
		name string
		cmd  *cobra.Command
		want bool
	}{
		// A completion script is shell source; a banner in front of it makes
		// `source <(vigolium completion bash)` execute the mascot.
		{"completion parent", completion, false},
		{"completion bash inherits from its parent", bash, false},
		// version prints its own identity line and would otherwise say it twice.
		{"version", version, false},
		// scan renders its own banner as the first line of its config summary,
		// and picks between two of them, so the root must not print one first.
		{"scan owns its banner", scan, false},
		// Everything else gets one, on stderr, where being wrong is cosmetic.
		{"traffic", traffic, true},
		{"nested db export", dbExport, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandWantsBanner(tc.cmd); got != tc.want {
				t.Errorf("commandWantsBanner(%q) = %v, want %v", tc.cmd.Name(), got, tc.want)
			}
		})
	}
}

func TestBannerDecisionIsInheritedBySubcommands(t *testing.T) {
	// `run probe` and `completion bash` both reach the hook as the child; the
	// decision has to come from the parent that owns it.
	parent := &cobra.Command{Use: "scan"}
	child := &cobra.Command{Use: "sub"}
	parent.AddCommand(child)

	if commandWantsBanner(child) {
		t.Error("a subcommand of a banner-free parent must inherit the decision")
	}

	other := &cobra.Command{Use: "traffic"}
	otherChild := &cobra.Command{Use: "sub"}
	other.AddCommand(otherChild)
	if !commandWantsBanner(otherChild) {
		t.Error("a subcommand of an ordinary parent still gets the banner")
	}
}
