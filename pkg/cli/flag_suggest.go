package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// flagErrorFunc augments cobra's flag-parse errors with a "did you mean" hint.
// Cobra suggests near-miss *subcommands* out of the box but says nothing for a
// mistyped *flag*, so `--module` (instead of `--modules`) dead-ends at a bare
// "unknown flag: --module". This closes that gap by pointing at the closest
// registered long flag on the command that actually failed to parse. It is
// installed once on rootCmd; cobra's FlagErrorFunc() walks up to the parent, so
// every subcommand inherits it.
func flagErrorFunc(cmd *cobra.Command, err error) error {
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		return err
	}
	// Only long-flag typos ("--module") get a suggestion. An unknown shorthand
	// carries a shortname group (GetSpecifiedShortnames) and rarely has a
	// meaningful near-match, so leave those untouched.
	typed := notExist.GetSpecifiedName()
	if notExist.GetSpecifiedShortnames() != "" || len(typed) < 2 {
		return err
	}
	// With no confident near-miss, say where the answer is rather than nothing.
	// A bare "unknown flag: --url" is a dead end; naming the command's own help
	// costs one line and is never misleading, which a guessed flag can be.
	best := closestFlagName(cmd, typed)
	if best == "" {
		return fmt.Errorf("%w\n\n  %s Run '%s --help' for this command's flags",
			err, terminal.InfoSymbol(), cmd.CommandPath())
	}
	return fmt.Errorf("%w\n\n  %s Did you mean %s? (run '%s --help' for all flags)",
		err, terminal.InfoSymbol(), terminal.BoldCyan("--"+best), cmd.CommandPath())
}

// closestFlagName returns the registered long flag on cmd nearest to typed by
// Levenshtein distance, or "" when nothing is close enough to be a confident
// suggestion. cmd.Flags() is the fully-merged set (local + inherited persistent)
// by the time flag parsing fails.
//
// The threshold used to be `max(2, len/3)`, which was too generous at the short
// end and produced the worst class of wrong answer. `vigolium traffic --url ...`
// was answered with "Did you mean --all?": three characters, edit distance two,
// so it cleared a floor of two — and --all is not a near-miss of --url, it is an
// unrelated flag that LIFTS the result cap. A suggestion that silently widens
// the query is worse than no suggestion, because a caller who takes it gets a
// plausible-looking answer to a question they did not ask.
//
// So the budget scales with the typed name throughout, and a distance that
// rewrites most of a short name no longer qualifies. Anything of five characters
// or fewer must match within one edit — a genuine typo (--modul for --module,
// --hosts for --host) still lands, while --url→--all does not.
func closestFlagName(cmd *cobra.Command, typed string) string {
	bestName := ""
	bestDist := -1
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		d := levenshtein(typed, f.Name)
		// Ties go to the first name in pflag's (lexical) visit order rather than
		// to whichever happened to be registered last, so the hint is stable
		// across builds.
		if bestDist == -1 || d < bestDist {
			bestName, bestDist = f.Name, d
		}
	})
	if bestDist == -1 {
		return ""
	}
	if bestDist <= suggestionBudget(typed) {
		return bestName
	}
	return ""
}

// suggestionBudget is the largest edit distance still considered a typo of
// typed. One edit for a short name, widening to a third of the name's length for
// longer ones, where the same distance leaves far more of the word intact.
func suggestionBudget(typed string) int {
	if len(typed) <= 5 {
		return 1
	}
	return len(typed) / 3
}

// levenshtein is the classic edit distance between a and b, computed with a
// two-row rolling buffer.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
