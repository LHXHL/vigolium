package cli

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// printSpiderFanOutTip writes the pre-scan fan-out hint for a multi-target
// spidering run: -c/--concurrency cannot speed this phase up, and the phase's own
// budget ceiling means most of a long target list is never reached. Both the text
// and the flags come from internal/runner, which owns the ceiling this is about
// and is also what prints the matching line when the ceiling actually trips — see
// runner.SpiderFanOutSuggestion for when a suggestion applies at all.
//
// Printed unconditionally rather than behind -v, because it only appears when the
// exact situation holds and it is the difference between covering the target list
// and covering eight of it.
func printSpiderFanOutTip(opts *types.Options, targetCount int) {
	flags, ok := runner.SpiderFanOutSuggestion(opts, targetCount)
	if !ok {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		terminal.TipPrefix(), terminal.Gray(runner.SpiderFanOutReason(targetCount)))
	fmt.Fprintf(os.Stderr, "         %s %s %s\n",
		terminal.Gray("run them as parallel child scans instead:"),
		terminal.HiCyan(flags),
		terminal.Gray("(one browser per child, each with its own budget)"))
}
