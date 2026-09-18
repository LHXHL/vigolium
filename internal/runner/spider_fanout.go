package runner

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/types"
)

// spiderFanOutSuggestedParallel is how many child scans the fan-out hint
// proposes. Five browsers is a load an ordinary laptop carries; the point of the
// hint is to get the operator off a strictly serial crawl, not to find their
// machine's limit.
const spiderFanOutSuggestedParallel = 5

// SpiderFanOutSuggestion returns the flags that would fan a multi-target
// spidering run out across child processes, and whether the suggestion applies.
//
// It exists because spidering is the one phase where the pace flags cannot help.
// It drives a browser rather than the executor, so -c/--concurrency (the
// executor's worker count) never reaches it, and its host loop is strictly
// serial — one crawl at a time, whatever the flags say. On top of that the phase
// stops after SpideringPhaseBudgetCap targets' worth of budget, so a long -T list
// is not merely slow, most of it is never reached: an operator who asked for 682
// hosts gets about eight and a skip warning at the end. The only real parallelism
// available is the -P fan-out, which runs each target as its own process with its
// own browser and its own ceiling.
//
// Every condition here mirrors one the -P fan-out itself enforces, because a hint
// naming a command that gets rejected — or silently degraded back to one serial
// scan — is worse than no hint. validateParallelScan admits -P > 1 only under
// --db-isolate or -S --split-by-host (anything else would share a database or an
// output file across concurrent scans), and needs a -T file to split in the first
// place: a -t-only or piped run has nothing to fan out and is warned back down to
// Parallel = 1. Suggesting --db-isolate to a -S run is pointless for a different
// reason — runScanCmd drops the flag with a warning there, leaving -P to fail the
// gate anyway. Flags already present are not repeated back.
//
// Lives here rather than in pkg/cli because both the pre-scan banner hint and the
// phase's own ceiling-reached line quote it, and pkg/cli imports this package
// (not the reverse) — one owner, so the two can never suggest different flags.
func SpiderFanOutSuggestion(opts *types.Options, targetCount int) (flags string, ok bool) {
	if opts == nil || !opts.SpideringEnabled {
		return "", false
	}
	// One target has nothing to fan out, and a run already fanning out needs no
	// advice about it.
	if targetCount < 2 || opts.Parallel > 1 {
		return "", false
	}
	// The fan-out splits a -T file and nothing else. TargetsSeededFromFile covers
	// the window after seedTargetsFromTargetFiles has promoted and cleared the
	// paths, which is where the phase-level caller runs.
	if len(opts.TargetsFilePaths) == 0 && !opts.TargetsSeededFromFile {
		return "", false
	}

	// Every arm ends in -P N; only the missing prerequisite varies.
	prefix := ""
	switch {
	case opts.Stateless && !opts.SplitByHost:
		prefix = "--split-by-host "
	case !opts.Stateless && !opts.DBIsolate:
		prefix = "--db-isolate "
	}
	return fmt.Sprintf("%s-P %d", prefix, min(targetCount, spiderFanOutSuggestedParallel)), true
}

// SpiderFanOutReason states why a serial crawl is the wrong shape for this
// target list. Two readings of the same fact: past the budget cap the ceiling is
// the headline — targets are dropped outright — while below it the only cost is
// wall clock. Telling an operator with 2 targets that "most won't be reached" is
// untrue, and a hint that overstates once is discounted from then on.
//
// Rendered here rather than in pkg/cli so it reads spideringPhaseBudgetCap
// directly: a hardcoded figure in the message would keep printing the old budget
// after the cap moved, and the operator sizes their fan-out against it.
func SpiderFanOutReason(targetCount int) string {
	if targetCount > spideringPhaseBudgetCap {
		return fmt.Sprintf(
			"spidering crawls one host at a time and stops after %d targets' worth of budget, so most of these %d won't be reached",
			spideringPhaseBudgetCap, targetCount)
	}
	return fmt.Sprintf("spidering crawls one host at a time, so these %d targets are crawled back to back", targetCount)
}
